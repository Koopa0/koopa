// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go bundles every testcontainers-backed test for the
// mcp package: the capture_inbox and actor-fallback cold-start paths,
// search_knowledge (corpus inclusion/exclusion, filters, relevance),
// plan_day position bounds, the propose_area / propose_goal /
// propose_project inert-draft flow, list_tasks readback, brief(reflection),
// and the tools/list enum-advertising probe.
//
// Run with:
//
//	go test -tags=integration ./internal/mcp/...
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/mcp/ops"
	"github.com/Koopa0/koopa/internal/note"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// setupServer truncates application-written rows, reconciles the agent
// registry the way cmd/mcp/main.go does at startup, and returns a Server
// wired to the shared test pool. callerAgent is set to learning-studio —
// the agent whose audit produced this suite — so every activity_events
// row in a happy-path test should carry that actor.
func setupServer(t *testing.T) *Server {
	t.Helper()
	truncateApplicationTables(t)
	registry := agent.NewBuiltinRegistry()
	agentStore := agent.NewStore(testPool)
	if _, err := agent.SyncToTable(t.Context(), registry, agentStore, nil, slog.Default()); err != nil {
		t.Fatalf("agent.SyncToTable: %v", err)
	}
	return NewServer(testPool, slog.Default(),
		WithRegistry(registry),
		WithCallerAgent("learning-studio"),
	)
}

// truncateApplicationTables clears every table an MCP handler can write to
// while preserving seed data from 002 (areas, topics, tags, feeds,
// learning_domains). agents stays intact because SyncToTable reconciles
// it in setupServer, not via TRUNCATE.
//
// CASCADE handles FK chains; RESTART IDENTITY keeps sequences deterministic
// across the TestMain-shared container.
func truncateApplicationTables(t *testing.T) {
	t.Helper()
	tables := []string{
		"activity_events",
		"daily_plan_items",
		"todos",
		"contents",
		"notes",
		"milestones",
		"goals",
		"projects",
	}
	sql := "TRUNCATE " + strings.Join(tables, ", ") + " RESTART IDENTITY CASCADE"
	if _, err := testPool.Exec(t.Context(), sql); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// activityActorFor reads the actor recorded by the audit_<entity> trigger
// for a single entity row. Empty string means no row exists — the trigger
// silently didn't fire, which is itself a test failure.
func activityActorFor(t *testing.T, entityType string, entityID uuid.UUID) string {
	t.Helper()
	var actor string
	err := testPool.QueryRow(t.Context(),
		"SELECT actor FROM activity_events WHERE entity_type = $1 AND entity_id = $2 ORDER BY occurred_at DESC LIMIT 1",
		entityType, entityID,
	).Scan(&actor)
	if err != nil {
		t.Fatalf("fetching activity_events for %s %s: %v", entityType, entityID, err)
	}
	return actor
}

// --- 1. capture_inbox end-to-end ---

// TestIntegration_ColdStart_CaptureInbox was Learning's first failure mode
// in the audit: activity_events_actor_fkey violation because koopa.actor
// was unset and the fallback 'system' wasn't in agents. With the registry
// seed and the withActorTx wrapper in place, this must write both the todo
// and the audit row with actor = learning-studio.
func TestIntegration_ColdStart_CaptureInbox(t *testing.T) {
	s := setupServer(t)

	_, out, err := callHandler(t, s.captureInbox, CaptureInboxInput{
		Title:       "test capture",
		Description: "cold-start test",
	})
	if err != nil {
		t.Fatalf("captureInbox: %v", err)
	}
	if out.Task.ID == uuid.Nil {
		t.Fatal("captureInbox returned zero task ID")
	}

	if got := activityActorFor(t, "todo", out.Task.ID); got != "learning-studio" {
		t.Errorf("activity_events.actor = %q, want %q (koopa.actor propagation)", got, "learning-studio")
	}
}

// --- 6. Actor fallback — 'system' must resolve ---

// TestIntegration_ActorFallbackToSystem guards the safety net. withActorTx
// is supposed to set koopa.actor on every covered write, but if a bug or an
// ops-level SQL statement bypasses it, the audit trigger's fallback string
// is the literal 'system'. The builtin registry registers that agent
// specifically so the FK resolves — if anyone removes it, this test fails
// and tells them why.
//
// The test writes a todo directly via the pool WITHOUT set_config. The
// audit trigger fires, reads an empty koopa.actor, falls back to 'system',
// and must succeed the activity_events FK.
func TestIntegration_ActorFallbackToSystem(t *testing.T) {
	setupServer(t) // reconciles registry so 'system' exists in agents

	var todoID uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, created_by, state, energy, priority)
		 VALUES ($1, $2, 'inbox', 'medium', 'medium')
		 RETURNING id`,
		"raw insert — no actor set", "human",
	).Scan(&todoID)
	if err != nil {
		t.Fatalf("raw todos insert: %v (if 'system' isn't seeded this FK fails)", err)
	}

	if got := activityActorFor(t, "todo", todoID); got != "system" {
		t.Errorf("activity_events.actor = %q, want %q (fallback path)", got, "system")
	}
}

func callHandlerAs[I, O any](t *testing.T, as string, handler func(context.Context, *mcp.CallToolRequest, I) (*mcp.CallToolResult, O, error), input I) (*mcp.CallToolResult, O, error) {
	t.Helper()
	ctx := context.WithValue(t.Context(), callerKey{}, as)
	return handler(ctx, nil, input)
}

func TestIntegration_ToolsListAdvertisesEnums(t *testing.T) {
	s := setupServer(t)

	// The MCP server's internal registry of tool schemas is not directly
	// exposed, but s.registeredNames + ops.All() gives the same pairing.
	// Walk the ops catalog, find tools with FieldEnums, and assert that
	// the generated schema (via the same jsonschema.ForType path) has
	// the expected enums. A lightweight proxy for what tools/list emits.
	s.logger.Info("integration_test: enum advertising probe", "registered", len(s.registeredNames))
	foundBriefMode, foundCaptureEnergy := false, false
	for _, m := range ops.All() {
		if m.Name == "brief" && len(m.FieldEnums["mode"]) > 0 {
			foundBriefMode = true
		}
		if m.Name == "capture_inbox" && len(m.FieldEnums["energy"]) > 0 {
			foundCaptureEnergy = true
		}
	}
	if !foundBriefMode {
		t.Error("brief.FieldEnums[mode] missing")
	}
	if !foundCaptureEnergy {
		t.Error("capture_inbox.FieldEnums[energy] missing")
	}
}

// ============================================================================
// Consolidated from a2a_integration_test.go (Track-1K test-file consolidation).
// ============================================================================

// --- seeding helpers ---

// seedSearchContent inserts a content row whose title and body both contain
// term, so websearch_to_tsquery('simple', term) matches via the generated
// search_vector. status is caller-chosen; 'draft' proves the INTERNAL search
// path (status != 'archived', no is_public gate) includes non-public rows.
func seedSearchContent(t *testing.T, slug, term, status string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO contents (slug, title, body, type, status)
		 VALUES ($1, $2, $3, 'article', $4) RETURNING id`,
		slug, term+" article", term+" "+term+" body", status,
	).Scan(&id); err != nil {
		t.Fatalf("seedSearchContent(%q): %v", slug, err)
	}
	return id
}

// seedSearchContentAt inserts a content row like seedSearchContent but with an
// explicit created_at, so date-boundary tests can place a row at a precise
// instant within a day. status defaults to 'draft' (internal-search visible).
func seedSearchContentAt(t *testing.T, slug, term string, createdAt time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO contents (slug, title, body, type, status, created_at)
		 VALUES ($1, $2, $3, 'article', 'draft', $4) RETURNING id`,
		slug, term+" article", term+" "+term+" body", createdAt,
	).Scan(&id); err != nil {
		t.Fatalf("seedSearchContentAt(%q): %v", slug, err)
	}
	return id
}

// seedSearchNote inserts a Zettelkasten note whose title and body contain term.
// kind must be a valid note_kind enum value.
func seedSearchNote(t *testing.T, slug, term, kind string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO notes (slug, title, body, kind, created_by)
		 VALUES ($1, $2, $3, $4, 'learning-studio') RETURNING id`,
		slug, term+" note", term+" note body", kind,
	).Scan(&id); err != nil {
		t.Fatalf("seedSearchNote(%q): %v", slug, err)
	}
	return id
}

// assertSearchResultShape checks the stable required fields of a single result
// envelope item. Does not assert order or relevance.
func assertSearchResultShape(t *testing.T, r *SearchKnowledgeResult) {
	t.Helper()
	if r.ID == "" {
		t.Errorf("result.id empty: %+v", r)
	}
	if r.Title == "" {
		t.Errorf("result.title empty: %+v", r)
	}
	if r.Slug == "" {
		t.Errorf("result.slug empty: %+v", r)
	}
	if r.CreatedAt == "" {
		t.Errorf("result.created_at empty: %+v", r)
	} else if _, err := time.Parse(time.RFC3339, r.CreatedAt); err != nil {
		t.Errorf("result.created_at %q not RFC3339: %v", r.CreatedAt, err)
	}
	switch r.SourceType {
	case SourceTypeContent:
		if r.ContentType == "" {
			t.Errorf("content result missing content_type: %+v", r)
		}
	case SourceTypeNote:
		if r.NoteKind == "" {
			t.Errorf("note result missing note_kind: %+v", r)
		}
	default:
		t.Errorf("unknown source_type %q (corpus is content|note only)", r.SourceType)
	}
}

// --- corpus inclusion ---

// TestIntegration_SearchKnowledge_CorpusInclusion seeds one content row and one
// note matching a unique term and asserts both corpora surface, each with a
// stable result shape and the correct source_type. No order assertion.
func TestIntegration_SearchKnowledge_CorpusInclusion(t *testing.T) {
	s := setupServer(t)
	const term = "zqxincl"
	cID := seedSearchContent(t, "sk-incl-content", term, "draft")
	nID := seedSearchNote(t, "sk-incl-note", term, "concept-note")

	_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term})
	if err != nil {
		t.Fatalf("searchKnowledge(%q) = %v, want success", term, err)
	}

	// Envelope invariants.
	if out.Query != term {
		t.Errorf("out.Query = %q, want %q", out.Query, term)
	}
	if out.Total != len(out.Results) {
		t.Errorf("out.Total = %d, want len(results) = %d", out.Total, len(out.Results))
	}

	var sawContent, sawNote bool
	for i := range out.Results {
		r := &out.Results[i]
		assertSearchResultShape(t, r)
		switch r.ID {
		case cID.String():
			sawContent = true
			if r.SourceType != SourceTypeContent {
				t.Errorf("content row source_type = %q, want %q", r.SourceType, SourceTypeContent)
			}
		case nID.String():
			sawNote = true
			if r.SourceType != SourceTypeNote {
				t.Errorf("note row source_type = %q, want %q", r.SourceType, SourceTypeNote)
			}
		}
	}
	if !sawContent {
		t.Error("content corpus not represented in results (expected the seeded content row)")
	}
	if !sawNote {
		t.Error("note corpus not represented in results (expected the seeded note)")
	}
}

// --- corpus exclusion ---

// TestIntegration_SearchKnowledge_CorpusExclusion seeds a confusable non-corpus
// note that matches the query term alongside one in-corpus content row, and
// asserts only corpus source types (content, note) surface in search_knowledge
// results. The in-corpus content row presence guards against a vacuous pass (a
// non-matching term would make exclusion trivially true).
func TestIntegration_SearchKnowledge_CorpusExclusion(t *testing.T) {
	s := setupServer(t)
	const term = "zqxexcl"
	seedSearchContent(t, "sk-excl-content", term, "draft")

	_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term})
	if err != nil {
		t.Fatalf("searchKnowledge(%q) = %v, want success", term, err)
	}

	if len(out.Results) == 0 {
		t.Fatal("expected at least the in-corpus content row; got 0 — term not matching, exclusion assertion would be vacuous")
	}
	for _, r := range out.Results {
		if r.SourceType != SourceTypeContent && r.SourceType != SourceTypeNote {
			t.Errorf("non-corpus entity leaked: source_type = %q", r.SourceType)
		}
	}
}

// --- empty result + envelope ---

// TestIntegration_SearchKnowledge_EmptyResult searches a nonsense term against a
// non-empty corpus and asserts a successful empty envelope: results:[] (not
// null), total 0, no error. The JSON marshal check pins the json-api nil-vs-[]
// rule directly on the wire shape.
func TestIntegration_SearchKnowledge_EmptyResult(t *testing.T) {
	s := setupServer(t)
	seedSearchContent(t, "sk-empty-content", "presentterm", "draft")

	const nonsense = "zzzznomatchqqqq"
	_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: nonsense})
	if err != nil {
		t.Fatalf("searchKnowledge(nonsense) = %v, want success with empty results", err)
	}
	if len(out.Results) != 0 {
		t.Errorf("len(results) = %d, want 0", len(out.Results))
	}
	if out.Total != 0 {
		t.Errorf("out.Total = %d, want 0", out.Total)
	}
	if out.Query != nonsense {
		t.Errorf("out.Query = %q, want %q", out.Query, nonsense)
	}

	b, mErr := json.Marshal(out)
	if mErr != nil {
		t.Fatalf("marshal output: %v", mErr)
	}
	if !strings.Contains(string(b), `"results":[]`) {
		t.Errorf("empty envelope must encode results as [], not null: %s", b)
	}
}

// --- filter: content_type ---

// TestIntegration_SearchKnowledge_ContentTypeFilter pins three behaviors:
// (1) a valid content_type narrows to the content branch and excludes notes;
// (2) a valid-but-unmatched content_type yields empty (no error);
// (3) an UNKNOWN content_type is rejected with a validation error (Track 1I
//
//	decision — strict enum validation, consistent with create_content; replaces
//	the Track 1G silent-empty characterization).
func TestIntegration_SearchKnowledge_ContentTypeFilter(t *testing.T) {
	s := setupServer(t)
	const term = "zqxctf"
	seedSearchContent(t, "sk-ctf-content", term, "draft") // type=article
	seedSearchNote(t, "sk-ctf-note", term, "concept-note")

	t.Run("article narrows to content, excludes notes", func(t *testing.T) {
		article := "article"
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, ContentType: &article})
		if err != nil {
			t.Fatalf("content_type=article: %v", err)
		}
		if len(out.Results) == 0 {
			t.Fatal("content_type=article should still match the seeded article")
		}
		for _, r := range out.Results {
			if r.SourceType != SourceTypeContent {
				t.Errorf("content_type=article leaked source_type %q", r.SourceType)
			}
		}
	})

	t.Run("valid unmatched type yields empty", func(t *testing.T) {
		essay := "essay"
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, ContentType: &essay})
		if err != nil {
			t.Fatalf("content_type=essay: %v", err)
		}
		if len(out.Results) != 0 {
			t.Errorf("content_type=essay (no essay seeded) = %d results, want 0", len(out.Results))
		}
	})

	t.Run("unknown type is rejected with a validation error", func(t *testing.T) {
		bogus := "banana-not-a-type"
		_, _, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, ContentType: &bogus})
		if err == nil {
			t.Fatal("unknown content_type must be rejected, not silently empty (Track 1I)")
		}
		if !strings.Contains(err.Error(), "unsupported content_type") {
			t.Errorf("error = %q, want containing %q", err, "unsupported content_type")
		}
	})
}

// --- filter: note_kind ---

// TestIntegration_SearchKnowledge_NoteKindFilter mirrors the content_type cases
// for notes: a valid note_kind narrows to the note branch and excludes content;
// a valid-but-unmatched note_kind yields empty.
func TestIntegration_SearchKnowledge_NoteKindFilter(t *testing.T) {
	s := setupServer(t)
	const term = "zqxnkf"
	seedSearchContent(t, "sk-nkf-content", term, "draft")
	seedSearchNote(t, "sk-nkf-note", term, "concept-note")

	t.Run("concept-note narrows to notes, excludes content", func(t *testing.T) {
		ck := "concept-note"
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, NoteKind: &ck})
		if err != nil {
			t.Fatalf("note_kind=concept-note: %v", err)
		}
		if len(out.Results) == 0 {
			t.Fatal("note_kind=concept-note should match the seeded note")
		}
		for _, r := range out.Results {
			if r.SourceType != SourceTypeNote {
				t.Errorf("note_kind filter leaked source_type %q", r.SourceType)
			}
		}
	})

	t.Run("unmatched kind yields empty", func(t *testing.T) {
		sn := "solve-note"
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, NoteKind: &sn})
		if err != nil {
			t.Fatalf("note_kind=solve-note: %v", err)
		}
		if len(out.Results) != 0 {
			t.Errorf("note_kind=solve-note (none seeded) = %d results, want 0", len(out.Results))
		}
	})
}

// --- filter: date range ---

// TestIntegration_SearchKnowledge_DateFilter seeds a row created "now" and
// proves the after/before window bounds it. Uses relative UTC dates so the
// assertion is deterministic regardless of wall clock. No order assertion.
func TestIntegration_SearchKnowledge_DateFilter(t *testing.T) {
	s := setupServer(t)
	const term = "zqxdate"
	seedSearchContent(t, "sk-date-content", term, "draft")

	now := time.Now().UTC()
	yesterday := now.AddDate(0, 0, -1).Format(time.DateOnly)
	tomorrow := now.AddDate(0, 0, 1).Format(time.DateOnly)

	t.Run("window enclosing now keeps the row", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, After: &yesterday, Before: &tomorrow})
		if err != nil {
			t.Fatalf("after=yesterday before=tomorrow: %v", err)
		}
		if len(out.Results) == 0 {
			t.Error("row created now must fall within [yesterday, tomorrow]")
		}
	})

	t.Run("before=yesterday excludes a now row", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, Before: &yesterday})
		if err != nil {
			t.Fatalf("before=yesterday: %v", err)
		}
		if len(out.Results) != 0 {
			t.Errorf("before=yesterday must exclude the now row; got %d", len(out.Results))
		}
	})

	t.Run("after=tomorrow excludes a now row", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, After: &tomorrow})
		if err != nil {
			t.Fatalf("after=tomorrow: %v", err)
		}
		if len(out.Results) != 0 {
			t.Errorf("after=tomorrow must exclude the now row; got %d", len(out.Results))
		}
	})
}

// --- limit cap ---

// TestIntegration_SearchKnowledge_LimitCaps seeds three matching content rows
// and asserts limit=1 caps the result count (and total == len(results)), while
// the default limit (omitted → 20) returns all three. Asserts counts only,
// never which rows — the cap is a count contract, not a ranking one.
func TestIntegration_SearchKnowledge_LimitCaps(t *testing.T) {
	s := setupServer(t)
	const term = "zqxlim"
	seedSearchContent(t, "sk-lim-1", term, "draft")
	seedSearchContent(t, "sk-lim-2", term, "draft")
	seedSearchContent(t, "sk-lim-3", term, "draft")

	t.Run("limit=1 caps to one", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, Limit: FlexInt(1)})
		if err != nil {
			t.Fatalf("limit=1: %v", err)
		}
		if len(out.Results) != 1 {
			t.Errorf("limit=1 → %d results, want 1", len(out.Results))
		}
		if out.Total != 1 {
			t.Errorf("out.Total = %d, want 1 (total == len(results))", out.Total)
		}
	})

	t.Run("default limit returns all three", func(t *testing.T) {
		// Exact count is load-bearing on seed-term uniqueness: setupServer
		// truncates contents+notes per test, and every term in this file uses a
		// distinct "zqx…" prefix, so only the three rows seeded above match.
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term})
		if err != nil {
			t.Fatalf("default limit: %v", err)
		}
		if len(out.Results) != 3 {
			t.Errorf("default limit → %d results, want 3", len(out.Results))
		}
	})
}

// --- semantic-branch degradation (embedder nil) ---

// TestIntegration_SearchKnowledge_EmbedderNilDegradation pins the production
// fallback path: when no embedder is wired (GEMINI_API_KEY unset — the harness
// default), search_knowledge runs FTS-only and still returns matching content
// with no error. The embedder-present-but-FAILING path is not exercised here:
// embedder is a concrete *embedder.Embedder with no interface seam, and project
// rules forbid introducing a single-impl interface purely for test injection
// (see report §coverage). FTS-only is the realistic, default deployment shape.
func TestIntegration_SearchKnowledge_EmbedderNilDegradation(t *testing.T) {
	s := setupServer(t)
	if s.embedder != nil {
		t.Fatal("harness must run search_knowledge with no embedder (FTS-only); embedder was wired")
	}

	const term = "zqxdegr"
	seedSearchContent(t, "sk-degr-content", term, "draft")

	_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term})
	if err != nil {
		t.Fatalf("FTS-only search must succeed with nil embedder: %v", err)
	}
	if len(out.Results) == 0 {
		t.Error("FTS-only search must still return the matching content row")
	}
}

// --- date filter: whole-day inclusive boundary (Track 1I) ---

// TestIntegration_SearchKnowledge_DateBoundaryInclusive proves the whole-day
// inclusive semantics end-to-end against real timestamptz rows. Three rows are
// seeded on the same day D (start, midday, last second) plus neighbors on D-1
// and D+1. The handler runs with the harness default timezone (UTC). It asserts
// that after=D and before=D each keep the entire day D and exclude the
// neighbors — pinning that `before=D` includes rows created during D (the
// same-day case Track 1G left untested), not just rows before D's start.
// Counts/membership only; no order assertion.
func TestIntegration_SearchKnowledge_DateBoundaryInclusive(t *testing.T) {
	s := setupServer(t)
	const term = "zqxbound"
	const day = "2026-05-22"

	mkUTC := func(s string) time.Time {
		ts, err := time.ParseInLocation(time.RFC3339, s, time.UTC)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return ts
	}

	startD := seedSearchContentAt(t, "sk-bound-start", term, mkUTC("2026-05-22T00:00:00Z"))
	midD := seedSearchContentAt(t, "sk-bound-mid", term, mkUTC("2026-05-22T12:30:00Z"))
	endD := seedSearchContentAt(t, "sk-bound-end", term, mkUTC("2026-05-22T23:59:59Z"))
	prevDay := seedSearchContentAt(t, "sk-bound-prev", term, mkUTC("2026-05-21T23:59:59Z"))
	nextDay := seedSearchContentAt(t, "sk-bound-next", term, mkUTC("2026-05-23T00:00:00Z"))

	ids := func(out SearchKnowledgeOutput) map[string]bool {
		m := make(map[string]bool, len(out.Results))
		for _, r := range out.Results {
			m[r.ID] = true
		}
		return m
	}

	t.Run("before=D includes the whole of day D, excludes D+1", func(t *testing.T) {
		d := day
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, Before: &d})
		if err != nil {
			t.Fatalf("before=%s: %v", day, err)
		}
		got := ids(out)
		for _, want := range []uuid.UUID{startD, midD, endD, prevDay} {
			if !got[want.String()] {
				t.Errorf("before=%s must keep row %s (created on/before D)", day, want)
			}
		}
		if got[nextDay.String()] {
			t.Errorf("before=%s must exclude the D+1 row %s", day, nextDay)
		}
	})

	t.Run("after=D includes the whole of day D, excludes D-1", func(t *testing.T) {
		d := day
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, After: &d})
		if err != nil {
			t.Fatalf("after=%s: %v", day, err)
		}
		got := ids(out)
		for _, want := range []uuid.UUID{startD, midD, endD, nextDay} {
			if !got[want.String()] {
				t.Errorf("after=%s must keep row %s (created on/after D start)", day, want)
			}
		}
		if got[prevDay.String()] {
			t.Errorf("after=%s must exclude the D-1 row %s", day, prevDay)
		}
	})

	t.Run("after=D and before=D keep exactly day D", func(t *testing.T) {
		d := day
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, After: &d, Before: &d})
		if err != nil {
			t.Fatalf("after=before=%s: %v", day, err)
		}
		got := ids(out)
		for _, want := range []uuid.UUID{startD, midD, endD} {
			if !got[want.String()] {
				t.Errorf("after=before=%s must keep day-D row %s", day, want)
			}
		}
		for _, drop := range []uuid.UUID{prevDay, nextDay} {
			if got[drop.String()] {
				t.Errorf("after=before=%s must exclude off-day row %s", day, drop)
			}
		}
	})
}

// --- source_types filter: end-to-end (Track 1I) ---

// TestIntegration_SearchKnowledge_SourceTypesEndToEnd closes the coverage gap
// flagged in the search-product contract: source_types selection was only unit-
// tested (TestSelectSources). It seeds one content row and one note matching the
// same term and asserts source_types=[content] returns only the content row,
// source_types=[note] only the note, both returns both, and an unknown token is
// rejected at the handler with an error (not a silent empty success).
func TestIntegration_SearchKnowledge_SourceTypesEndToEnd(t *testing.T) {
	s := setupServer(t)
	const term = "zqxsrc"
	cID := seedSearchContent(t, "sk-src-content", term, "draft")
	nID := seedSearchNote(t, "sk-src-note", term, "concept-note")

	t.Run("content only returns content, excludes note", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, SourceTypes: []string{SourceTypeContent}})
		if err != nil {
			t.Fatalf("source_types=[content]: %v", err)
		}
		if len(out.Results) != 1 || out.Results[0].ID != cID.String() {
			t.Errorf("source_types=[content] = %d results, want exactly the content row %s", len(out.Results), cID)
		}
	})

	t.Run("note only returns note, excludes content", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, SourceTypes: []string{SourceTypeNote}})
		if err != nil {
			t.Fatalf("source_types=[note]: %v", err)
		}
		if len(out.Results) != 1 || out.Results[0].ID != nID.String() {
			t.Errorf("source_types=[note] = %d results, want exactly the note %s", len(out.Results), nID)
		}
	})

	t.Run("both returns content and note", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, SourceTypes: []string{SourceTypeContent, SourceTypeNote}})
		if err != nil {
			t.Fatalf("source_types=[content,note]: %v", err)
		}
		// Exact count is load-bearing on seed-term uniqueness: setupServer
		// truncates contents+notes per test, and "zqxsrc" is unique to this
		// test, so only the one content row + one note seeded above match.
		if len(out.Results) != 2 {
			t.Errorf("source_types=[content,note] = %d results, want 2", len(out.Results))
		}
	})

	t.Run("unknown source_type rejected, not silent empty", func(t *testing.T) {
		_, _, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, SourceTypes: []string{"bookmark"}})
		if err == nil {
			t.Fatal("unknown source_type must error, not return empty success")
		}
		if !strings.Contains(err.Error(), "unsupported source_type") {
			t.Errorf("error = %q, want containing %q", err, "unsupported source_type")
		}
	})
}

// --- project filter rejection: end-to-end (Track 1I) ---

// TestIntegration_SearchKnowledge_ProjectRejected pins that a non-empty project
// filter is rejected at the MCP handler boundary with an unsupported_filter
// error, against a corpus that WOULD match the query — proving the rejection is
// the project field, not an empty corpus. An empty project value is ignored
// (treated as absent) and the search succeeds.
func TestIntegration_SearchKnowledge_ProjectRejected(t *testing.T) {
	s := setupServer(t)
	const term = "zqxproj"
	seedSearchContent(t, "sk-proj-content", term, "draft")

	t.Run("non-empty project rejected", func(t *testing.T) {
		p := "koopa"
		_, _, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, Project: &p})
		if err == nil {
			t.Fatal("non-empty project must be rejected as unsupported_filter")
		}
		if !strings.Contains(err.Error(), "unsupported_filter") {
			t.Errorf("error = %q, want containing %q", err, "unsupported_filter")
		}
	})

	t.Run("empty project ignored, search succeeds", func(t *testing.T) {
		empty := ""
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, Project: &empty})
		if err != nil {
			t.Fatalf("empty project must be treated as absent: %v", err)
		}
		if len(out.Results) == 0 {
			t.Error("empty project must not filter out the matching content row")
		}
	})
}

// ============================================================================
// Consolidated from search_relevance_eval_test.go (Track-1K test-file consolidation).
// ============================================================================

// --- tier-1 seed loaders (synthetic; mirror search-relevance-seed-plan.md) ---

// seedRelContent inserts a contents row whose title and body both carry term so
// websearch_to_tsquery('simple', term) matches. type/status are caller-chosen.
// A non-published status leaves published_at NULL (chk_content_publication).
func seedRelContent(t *testing.T, slug, term, ctype, status string, createdAt *time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	var err error
	if createdAt != nil {
		err = testPool.QueryRow(t.Context(),
			`INSERT INTO contents (slug, title, body, type, status, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
			slug, term+" title", term+" "+term+" body", ctype, status, *createdAt,
		).Scan(&id)
	} else {
		err = testPool.QueryRow(t.Context(),
			`INSERT INTO contents (slug, title, body, type, status)
			 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
			slug, term+" title", term+" "+term+" body", ctype, status,
		).Scan(&id)
	}
	if err != nil {
		t.Fatalf("seedRelContent(%q): %v", slug, err)
	}
	return id
}

// seedRelNote inserts a notes row carrying term, with caller-chosen kind and
// maturity (so the archived-note asymmetry control can set maturity='archived').
func seedRelNote(t *testing.T, slug, term, kind, maturity string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO notes (slug, title, body, kind, maturity, created_by)
		 VALUES ($1, $2, $3, $4, $5, 'learning-studio') RETURNING id`,
		slug, term+" note", term+" note body", kind, maturity,
	).Scan(&id); err != nil {
		t.Fatalf("seedRelNote(%q): %v", slug, err)
	}
	return id
}

// relSeeder seeds one seed_id row and reports whether it has a stable id worth
// pinning in the evaluator (content/note do; non-corpus controls do not).
type relSeeder func(t *testing.T) (uuid.UUID, bool)

// tier1SeederRegistry maps every seed_id reachable by the NEG/FLT subset to a
// seeder. Terms match the fixtures' verbatim queries exactly. Only the seeds
// needed by NEG-01..05 / FLT-01..08 are registered (Track 1K scope).
func tier1SeederRegistry() map[string]relSeeder {
	// at parses a fixed RFC3339 seed timestamp; the strings are compile-time
	// constants, so a parse error is a typo in this file — surfaced via the
	// seeder's own *testing.T rather than a panic.
	at := func(t *testing.T, rfc3339 string) *time.Time {
		t.Helper()
		ts, err := time.Parse(time.RFC3339, rfc3339)
		if err != nil {
			t.Fatalf("tier1SeederRegistry: bad timestamp %q: %v", rfc3339, err)
		}
		return &ts
	}
	noID := func(seed func(*testing.T)) relSeeder {
		return func(t *testing.T) (uuid.UUID, bool) { seed(t); return uuid.Nil, false }
	}
	withID := func(seed func(*testing.T) uuid.UUID) relSeeder {
		return func(t *testing.T) (uuid.UUID, bool) { return seed(t), true }
	}

	return map[string]relSeeder{
		// NEG controls (corpus boundary).
		"C-ARCHIVED": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-archived", "zqxarchcontent", "article", "archived", nil)
		}),
		"N-ARCHIVED": withID(func(t *testing.T) uuid.UUID {
			return seedRelNote(t, "rel-n-archived", "zqxarchnote", "reading-note", "archived")
		}),

		// FLT-01/02 — source_types narrowing.
		"C-SRC": withID(func(t *testing.T) uuid.UUID { return seedRelContent(t, "rel-c-src", "zqxsrc", "article", "draft", nil) }),
		"N-SRC": withID(func(t *testing.T) uuid.UUID { return seedRelNote(t, "rel-n-src", "zqxsrc", "concept-note", "seed") }),

		// FLT-03 — content_type narrowing.
		"C-CTF-ARTICLE": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-ctf-article", "zqxctf", "article", "draft", nil)
		}),
		"C-CTF-ESSAY": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-ctf-essay", "zqxctf", "essay", "draft", nil)
		}),
		"N-CTF": withID(func(t *testing.T) uuid.UUID { return seedRelNote(t, "rel-n-ctf", "zqxctf", "concept-note", "seed") }),

		// FLT-04 — note_kind narrowing.
		"N-NKF-SOLVE": withID(func(t *testing.T) uuid.UUID { return seedRelNote(t, "rel-n-nkf-solve", "zqxnkf", "solve-note", "seed") }),
		"N-NKF-CONCEPT": withID(func(t *testing.T) uuid.UUID {
			return seedRelNote(t, "rel-n-nkf-concept", "zqxnkf", "concept-note", "seed")
		}),
		"C-NKF": withID(func(t *testing.T) uuid.UUID { return seedRelContent(t, "rel-c-nkf", "zqxnkf", "article", "draft", nil) }),

		// FLT-05 — whole-day-inclusive date window, anchor 2026-05-22 (UTC).
		"C-DAY-START": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-day-start", "zqxbound", "article", "draft", at(t, "2026-05-22T00:00:00Z"))
		}),
		"C-DAY-MID": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-day-mid", "zqxbound", "article", "draft", at(t, "2026-05-22T12:30:00Z"))
		}),
		"C-DAY-END": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-day-end", "zqxbound", "article", "draft", at(t, "2026-05-22T23:59:59Z"))
		}),
		"C-DAY-PREV": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-day-prev", "zqxbound", "article", "draft", at(t, "2026-05-21T23:59:59Z"))
		}),
		"C-DAY-NEXT": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-day-next", "zqxbound", "article", "draft", at(t, "2026-05-23T00:00:00Z"))
		}),

		// FLT-06/07/08 — rejection probes share C-VALID (proves the rejection
		// is the filter, not an empty corpus).
		"C-VALID": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-valid", "zqxreject", "article", "draft", nil)
		}),

		// FLT-01..04 — typed corpus rows the new judgment-set fixtures refer to
		// by generic seed_ids. Term "go" matches the fixtures' verbatim query.
		"content:article:any": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-article-any", "go", "article", "draft", nil)
		}),
		"content:til:any": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-til-any", "go", "til", "draft", nil)
		}),
		"note:concept-note:any": withID(func(t *testing.T) uuid.UUID {
			return seedRelNote(t, "rel-n-concept-any", "go", "concept-note", "seed")
		}),
		"note:solve-note:any": withID(func(t *testing.T) uuid.UUID {
			return seedRelNote(t, "rel-n-solve-any", "go", "solve-note", "seed")
		}),

		// FLT-05 — dated articles bracketing the after=2026-01-01 / before=2026-03-31
		// window. The -2025-12-01 row sits before the window; -2026-02-15 sits inside.
		"content:article:dated-2025-12-01": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-article-2025-12-01", "go", "article", "draft", at(t, "2025-12-01T00:00:00Z"))
		}),
		"content:article:dated-2026-02-15": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-article-2026-02-15", "go", "article", "draft", at(t, "2026-02-15T00:00:00Z"))
		}),

		// FLT-06 — enough matching articles that limit=5 actually caps a non-empty
		// remainder. 12 > 10 leaves room for any future stricter "10-plus" reading.
		"content:article:bulk-10-plus": noID(func(t *testing.T) {
			for i := range 12 {
				slug := fmt.Sprintf("rel-c-bulk-%02d", i)
				seedRelContent(t, slug, "go", "article", "draft", nil)
			}
		}),
	}
}

// requiredSeedIDs is the sorted union of seed_ids referenced by the selected
// fixtures' seed_requirements.
func requiredSeedIDs(selected []searchFixture) []string {
	set := map[string]struct{}{}
	for i := range selected {
		for _, s := range selected[i].SeedRequirements {
			set[s] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// seedTier1Corpus seeds every required seed_id once and returns the id of each
// content/note row (the rows the evaluator pins by id). It fatals if a required
// seed has no registered seeder — that is a coverage gap, not a guess.
func seedTier1Corpus(t *testing.T, required []string, registry map[string]relSeeder) map[string]uuid.UUID {
	t.Helper()
	ids := map[string]uuid.UUID{}
	for _, seedID := range required {
		seed, ok := registry[seedID]
		if !ok {
			t.Fatalf("no seeder registered for required seed_id %q", seedID)
		}
		if id, hasID := seed(t); hasID {
			ids[seedID] = id
		}
	}
	return ids
}

// --- evaluator ---

// tier1Expectation is the per-fixture test oracle for the `results` outcome:
// which seeded rows must appear / be absent, the narrowing every returned row
// must satisfy, and an optional exact result count (used to verify limit-cap
// behavior). Empty / zero fields mean "no constraint". Keys reference seed_ids
// from docs/testing/search-relevance-judgment-set.md; empty/validation_error
// fixtures need no entry — their outcome branch in evaluateFixture is
// self-pinning. A results-outcome fixture missing here fails loudly (see the
// oracle guard).
type tier1Expectation struct {
	mustAppear     []string // seed_ids that must be in results
	mustBeAbsent   []string // seed_ids that must NOT be in results
	allSourceType  string   // every result.SourceType must equal this
	allContentType string   // every result.ContentType must equal this
	allNoteKind    string   // every result.NoteKind must equal this
	exactCount     int      // if non-zero, len(results) must equal this — used for limit-cap fixtures
}

// tier1Expectations is keyed by fixture_id. Each entry pins the rows the
// fixture's seed_requirements explicitly name, so the oracle stays aligned
// with the judgment-set declaration rather than incidental corpus state.
var tier1Expectations = map[string]tier1Expectation{
	// FLT-01: content_type=article filters out the til content and the note.
	"FLT-01": {
		mustAppear:     []string{"content:article:any"},
		mustBeAbsent:   []string{"content:til:any", "note:solve-note:any"},
		allSourceType:  SourceTypeContent,
		allContentType: "article",
	},
	// FLT-02: content_type=til filters out the plain article.
	"FLT-02": {
		mustAppear:     []string{"content:til:any"},
		mustBeAbsent:   []string{"content:article:any"},
		allSourceType:  SourceTypeContent,
		allContentType: "til",
	},
	// FLT-03: note_kind=solve-note implies source_types=[note] and excludes content.
	"FLT-03": {
		mustAppear:    []string{"note:solve-note:any"},
		mustBeAbsent:  []string{"content:article:any"},
		allSourceType: SourceTypeNote,
		allNoteKind:   "solve-note",
	},
	// FLT-04: source_types=[content] filters out every seeded note.
	"FLT-04": {
		mustAppear:    []string{"content:article:any"},
		mustBeAbsent:  []string{"note:concept-note:any"},
		allSourceType: SourceTypeContent,
	},
	// FLT-05: after=2026-01-01 / before=2026-03-31 admits the 2026-02-15 row
	// and rejects the 2025-12-01 row. No source-type / type narrowing applies.
	"FLT-05": {
		mustAppear:   []string{"content:article:dated-2026-02-15"},
		mustBeAbsent: []string{"content:article:dated-2025-12-01"},
	},
	// FLT-06: limit=5 with >5 matching rows must return exactly 5. The bulk
	// seeder inserts 12 articles, so matching count > limit is guaranteed.
	"FLT-06": {exactCount: 5},
}

// evalOutcome is the structured result for one fixture run.
type evalOutcome struct {
	FixtureID       string
	Status          string // pass | fail | skip
	Reason          string
	ObservedIDs     []string
	ObservedTypes   []string
	ExpectedSummary string
}

// expectedRejectionSubstring derives, from the structured filters alone, the
// substring the handler's validation error must contain. It mirrors
// validateSearchKnowledgeInput — no prose is read.
func expectedRejectionSubstring(f *searchFixtureFilters) string {
	if f.Project != "" {
		return "unsupported_filter"
	}
	for _, st := range f.SourceTypes {
		if st != SourceTypeContent && st != SourceTypeNote {
			return "unsupported source_type"
		}
	}
	if f.ContentType != "" && !content.Type(f.ContentType).Valid() {
		return "unsupported content_type"
	}
	if f.NoteKind != "" && !note.Kind(f.NoteKind).Valid() {
		return "unsupported note_kind"
	}
	return ""
}

// buildSearchInput maps a fixture's verbatim query + structured filters onto a
// SearchKnowledgeInput, exactly as specified — no inference.
func buildSearchInput(fx *searchFixture) SearchKnowledgeInput {
	in := SearchKnowledgeInput{Query: fx.Query}
	f := &fx.Filters
	if len(f.SourceTypes) > 0 {
		in.SourceTypes = f.SourceTypes
	}
	if f.ContentType != "" {
		ct := f.ContentType
		in.ContentType = &ct
	}
	if f.NoteKind != "" {
		nk := f.NoteKind
		in.NoteKind = &nk
	}
	if f.Project != "" {
		p := f.Project
		in.Project = &p
	}
	if f.After != "" {
		a := f.After
		in.After = &a
	}
	if f.Before != "" {
		b := f.Before
		in.Before = &b
	}
	if f.Limit > 0 {
		in.Limit = FlexInt(f.Limit)
	}
	return in
}

func observedResults(out SearchKnowledgeOutput) (ids, types []string) {
	for i := range out.Results {
		ids = append(ids, out.Results[i].ID)
		types = append(types, out.Results[i].SourceType)
	}
	return ids, types
}

func summarizeExpectation(e *tier1Expectation) string {
	var parts []string
	if e.exactCount > 0 {
		parts = append(parts, fmt.Sprintf("exactly %d results", e.exactCount))
	}
	if len(e.mustAppear) > 0 {
		parts = append(parts, "present="+strings.Join(e.mustAppear, ","))
	}
	if len(e.mustBeAbsent) > 0 {
		parts = append(parts, "absent="+strings.Join(e.mustBeAbsent, ","))
	}
	if e.allSourceType != "" {
		parts = append(parts, "all source_type="+e.allSourceType)
	}
	if e.allContentType != "" {
		parts = append(parts, "all content_type="+e.allContentType)
	}
	if e.allNoteKind != "" {
		parts = append(parts, "all note_kind="+e.allNoteKind)
	}
	if len(parts) == 0 {
		return "≥1 result"
	}
	return strings.Join(parts, "; ")
}

// evaluateFixture runs one fixture's query+filters through search_knowledge and
// scores ONLY mechanical criteria per its expected_outcome. It never asserts
// rank order or relevance.
func evaluateFixture(t *testing.T, s *Server, fx *searchFixture, ids map[string]uuid.UUID) evalOutcome {
	t.Helper()
	_, out, err := callHandler(t, s.searchKnowledge, buildSearchInput(fx))
	oc := evalOutcome{FixtureID: fx.FixtureID}

	switch fx.ExpectedOutcome {
	case "validation_error":
		sub := expectedRejectionSubstring(&fx.Filters)
		oc.ExpectedSummary = fmt.Sprintf("validation error containing %q", sub)
		switch {
		case err == nil:
			oc.Status, oc.Reason = "fail", "expected a validation error, got success"
		case sub != "" && !strings.Contains(err.Error(), sub):
			oc.Status, oc.Reason = "fail", fmt.Sprintf("error %q missing expected substring %q", err.Error(), sub)
		default:
			oc.Status, oc.Reason = "pass", "rejected before any store call"
		}

	case "empty":
		oc.ExpectedSummary = "empty success — no corpus leak"
		oc.ObservedIDs, oc.ObservedTypes = observedResults(out)
		switch {
		case err != nil:
			oc.Status, oc.Reason = "fail", fmt.Sprintf("expected empty success, got error: %v", err)
		case len(out.Results) != 0:
			oc.Status, oc.Reason = "fail", fmt.Sprintf("expected 0 results (no leak), got %d", len(out.Results))
		default:
			oc.Status, oc.Reason = "pass", "no leak from the non-corpus / archived seed"
		}

	case "results":
		// A results-outcome fixture MUST have an oracle entry; without one the
		// run would silently assert nothing beyond "≥1 result". Fail loudly.
		exp, ok := tier1Expectations[fx.FixtureID]
		oc.ObservedIDs, oc.ObservedTypes = observedResults(out)
		if !ok {
			oc.Status = "fail"
			oc.Reason = "expected_outcome=results but no tier1Expectations oracle entry"
			return oc
		}
		oc.ExpectedSummary = summarizeExpectation(&exp)
		oc.Status, oc.Reason = scoreResults(out, err, &exp, ids)

	default:
		oc.Status = "skip"
		oc.Reason = fmt.Sprintf("expected_outcome %q is not tier-1 mechanical", fx.ExpectedOutcome)
	}
	return oc
}

// scoreResults applies the `results` expectation: success, ≥1 row, required
// rows present, excluded rows absent, and the per-result narrowing. Membership
// checks are by seed id (timezone-robust); narrowing checks are by result field
// — never by rank.
func scoreResults(out SearchKnowledgeOutput, err error, exp *tier1Expectation, ids map[string]uuid.UUID) (status, reason string) {
	if err != nil {
		return "fail", fmt.Sprintf("expected results, got error: %v", err)
	}
	if exp.exactCount > 0 && len(out.Results) != exp.exactCount {
		return "fail", fmt.Sprintf("expected exactly %d results (limit cap), got %d", exp.exactCount, len(out.Results))
	}
	if len(out.Results) == 0 {
		return "fail", "expected ≥1 result, got 0 (zero-result-with-match)"
	}
	got := map[string]bool{}
	for i := range out.Results {
		got[out.Results[i].ID] = true
	}
	for _, key := range exp.mustAppear {
		if !got[ids[key].String()] {
			return "fail", fmt.Sprintf("required row %s absent from results", key)
		}
	}
	for _, key := range exp.mustBeAbsent {
		if got[ids[key].String()] {
			return "fail", fmt.Sprintf("excluded row %s leaked into results", key)
		}
	}
	for i := range out.Results {
		r := &out.Results[i]
		if exp.allSourceType != "" && r.SourceType != exp.allSourceType {
			return "fail", fmt.Sprintf("result %s source_type=%q, want %q", r.ID, r.SourceType, exp.allSourceType)
		}
		if exp.allContentType != "" && r.ContentType != exp.allContentType {
			return "fail", fmt.Sprintf("result %s content_type=%q, want %q", r.ID, r.ContentType, exp.allContentType)
		}
		if exp.allNoteKind != "" && r.NoteKind != exp.allNoteKind {
			return "fail", fmt.Sprintf("result %s note_kind=%q, want %q", r.ID, r.NoteKind, exp.allNoteKind)
		}
	}
	return "pass", "narrowing + presence/absence hold"
}

// --- the tier-1 run ---

// TestIntegration_SearchRelevance_Tier1 is the fixture loader / evaluation
// harness for the tier-1 mechanical subset. It parses the judgment set, selects
// NEG-01..05 / FLT-01..08, confirms every required seed resolves, seeds the
// corpus once into the integration testcontainer, and evaluates each fixture
// mechanically. No ranking, relevance, or vector behavior is asserted.
func TestIntegration_SearchRelevance_Tier1(t *testing.T) {
	fixtures := loadSearchFixtures(t)
	selected, skipped := selectTier1(fixtures)

	t.Logf("tier-1 selection: %d fixtures; skipped %d non-tier-1 fixtures", len(selected), len(skipped))
	for _, sk := range skipped {
		t.Logf("  skip %-7s — %s", sk.FixtureID, sk.Reason)
	}

	registry := tier1SeederRegistry()
	required := requiredSeedIDs(selected)

	t.Run("seed references resolve", func(t *testing.T) {
		for _, seedID := range required {
			if _, ok := registry[seedID]; !ok {
				t.Errorf("seed_id %q required by a selected fixture has no registered seeder", seedID)
			}
		}
	})

	s := setupServer(t)
	ids := seedTier1Corpus(t, required, registry)

	// Evaluate and collect OUTSIDE t.Run so the shared outcomes slice is never
	// touched from a subtest closure — the run is sequential today, but keeping
	// the append off the closure removes a latent data race if a future edit
	// adds t.Parallel(). The named subtest carries only the per-fixture assertion.
	outcomes := make([]evalOutcome, 0, len(selected))
	for i := range selected {
		fx := &selected[i]
		oc := evaluateFixture(t, s, fx, ids)
		outcomes = append(outcomes, oc)
		t.Run(fx.FixtureID, func(t *testing.T) {
			if oc.Status != "pass" {
				t.Errorf("%s [%s]: %s\n  expected: %s\n  observed ids:   %v\n  observed types: %v",
					oc.FixtureID, oc.Status, oc.Reason, oc.ExpectedSummary, oc.ObservedIDs, oc.ObservedTypes)
			}
		})
	}

	logTier1Results(t, outcomes)
}

// logTier1Results writes the structured per-fixture result table to the test
// log: fixture_id, status, reason, observed ids/types, expected summary.
func logTier1Results(t *testing.T, outcomes []evalOutcome) {
	t.Helper()
	var b strings.Builder
	b.WriteString("\n=== Tier-1 fixture evaluation results ===\n")
	var pass, fail, skip int
	for i := range outcomes {
		oc := &outcomes[i]
		switch oc.Status {
		case "pass":
			pass++
		case "fail":
			fail++
		default:
			skip++
		}
		fmt.Fprintf(&b, "%-7s %-5s %s\n", oc.FixtureID, oc.Status, oc.Reason)
		fmt.Fprintf(&b, "         expected: %s\n", oc.ExpectedSummary)
		fmt.Fprintf(&b, "         observed: ids=%v types=%v\n", oc.ObservedIDs, oc.ObservedTypes)
	}
	fmt.Fprintf(&b, "totals: %d pass, %d fail, %d skip (of %d)\n", pass, fail, skip, len(outcomes))
	t.Log(b.String())
}

// --- plan_day position bounds (#13) ---

// seedTodoState inserts a todo in the given state and returns its id. plan_day
// requires todos in state=todo; the registry sync in setupServer seeds the
// default created_by='human' agent so the FK resolves.
func seedTodoState(t *testing.T, title, state string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, state) VALUES ($1, $2::todo_state) RETURNING id`,
		title, state,
	).Scan(&id); err != nil {
		t.Fatalf("seeding todo %q (state=%s): %v", title, state, err)
	}
	return id
}

// countPlanItems returns how many daily_plan_items rows exist for a todo.
func countPlanItems(t *testing.T, todoID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM daily_plan_items WHERE todo_id = $1`, todoID,
	).Scan(&n); err != nil {
		t.Fatalf("counting plan items: %v", err)
	}
	return n
}

// TestIntegration_PlanDay_PositionOutOfRangeRejected guards the position bound:
// createPlanItemTx bounds the caller-supplied position to [0, maxPlanPosition]
// (100000) so the int32 cast cannot overflow. A position above the ceiling or
// below zero must be rejected, and because the whole plan_day write runs inside
// a single withActorTx, the rejection rolls back the DeletePlannedByDate that
// opened the idempotent-replace window — leaving zero daily_plan_items written.
//
// plan_day is author-gated to planner, so the call goes through callHandlerAs("planner").
func TestIntegration_PlanDay_PositionOutOfRangeRejected(t *testing.T) {
	s := setupServer(t)
	todoID := seedTodoState(t, "bounded-plan-item", "todo")

	tests := []struct {
		name     string
		position int
	}{
		{name: "above maxPlanPosition", position: maxPlanPosition + 1},
		{name: "well above ceiling", position: 1_000_000},
		{name: "negative position", position: -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := callHandlerAs(t, "planner", s.planDay, PlanDayInput{
				Items: []PlanDayItem{
					{TaskID: todoID.String(), Position: tc.position},
				},
			})
			if err == nil {
				t.Fatalf("plan_day accepted out-of-range position %d; want rejection", tc.position)
			}
			if !strings.Contains(err.Error(), "out of range") {
				t.Errorf("error = %q, want it to name the out-of-range position", err)
			}
			if got := countPlanItems(t, todoID); got != 0 {
				t.Errorf("daily_plan_items for todo = %d, want 0 (tx rollback on rejection)", got)
			}
		})
	}

	// Control: an in-range position for the same todo succeeds, proving the
	// rejection above is the bounds gate and not a setup error.
	_, out, err := callHandlerAs(t, "planner", s.planDay, PlanDayInput{
		Items: []PlanDayItem{
			{TaskID: todoID.String(), Position: 1},
		},
	})
	if err != nil {
		t.Fatalf("plan_day with in-range position: %v", err)
	}
	if out.ItemsCreated != 1 {
		t.Errorf("items_created = %d, want 1 for the in-range control", out.ItemsCreated)
	}
	if got := countPlanItems(t, todoID); got != 1 {
		t.Errorf("daily_plan_items for todo = %d, want 1 after in-range plan", got)
	}
}

func deleteProposedAreas(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(),
		`DELETE FROM areas WHERE status = 'proposed'`,
	); err != nil {
		t.Fatalf("cleaning up proposed areas: %v", err)
	}
}

// TestIntegration_ProposeArea_AsPlanner drives propose_area and asserts the
// inert-draft contract on the persisted row: status=proposed, created_by=the
// proposing agent, and a slug derived from the name.
func TestIntegration_ProposeArea_AsPlanner(t *testing.T) {
	s := setupServer(t)
	t.Cleanup(func() { deleteProposedAreas(t) })

	_, out, err := callHandlerAs(t, "planner", s.proposeArea, ProposeAreaInput{
		Name:        "Backend Studio",
		Description: "Sustained backend craft.",
		Rationale:   "Recurring backend themes in recent sessions.",
	})
	if err != nil {
		t.Fatalf("proposeArea: %v", err)
	}
	if out.Area == nil || out.Area.ID == uuid.Nil {
		t.Fatal("proposeArea returned no area / zero ID")
	}
	if out.Area.Slug != "backend-studio" {
		t.Errorf("output slug = %q, want %q (derived from name)", out.Area.Slug, "backend-studio")
	}

	var status, createdBy string
	if err := testPool.QueryRow(t.Context(),
		`SELECT status, created_by FROM areas WHERE id = $1`, out.Area.ID,
	).Scan(&status, &createdBy); err != nil {
		t.Fatalf("reading proposed area: %v", err)
	}
	if status != "proposed" {
		t.Errorf("persisted status = %q, want %q (agent proposals land inert)", status, "proposed")
	}
	if createdBy != "planner" {
		t.Errorf("persisted created_by = %q, want %q", createdBy, "planner")
	}
}

// TestIntegration_ProposeArea_CallerGate asserts the registered-caller gate:
// the zero-privilege "unknown" fallback and a fabricated name are refused
// before any write.
func TestIntegration_ProposeArea_CallerGate(t *testing.T) {
	s := setupServer(t)
	t.Cleanup(func() { deleteProposedAreas(t) })

	for _, caller := range []string{"unknown", "fabricated-agent"} {
		_, _, err := callHandlerAs(t, caller, s.proposeArea, ProposeAreaInput{Name: "Should Never Persist"})
		if err == nil {
			t.Errorf("proposeArea as %q err = nil, want registered-caller refusal", caller)
		}
	}

	var count int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM areas WHERE status = 'proposed'`,
	).Scan(&count); err != nil {
		t.Fatalf("counting proposed areas: %v", err)
	}
	if count != 0 {
		t.Errorf("proposed area count = %d, want 0 (gate must precede any write)", count)
	}
}

// TestIntegration_ProposeArea_BlankNameRejected asserts the handler rejects a
// blank name before any write (the chk_area_name_not_blank CHECK would also
// fire, but the handler validates first for a clean error).
func TestIntegration_ProposeArea_BlankNameRejected(t *testing.T) {
	s := setupServer(t)

	for _, name := range []string{"", "   ", "!!!"} {
		if _, _, err := callHandlerAs(t, "planner", s.proposeArea, ProposeAreaInput{Name: name}); err == nil {
			t.Errorf("proposeArea(name=%q) err = nil, want rejection", name)
		}
	}
}

// TestIntegration_ProposeGoal_AsPlanner drives propose_goal with milestones
// under an existing ACTIVE area and asserts: goal status=proposed,
// created_by=planner, area_id resolved, and milestones persisted in order.
func TestIntegration_ProposeGoal_AsPlanner(t *testing.T) {
	s := setupServer(t)

	// Resolve a seeded active area to file under.
	var areaID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`SELECT id FROM areas WHERE slug = 'learning'`,
	).Scan(&areaID); err != nil {
		t.Fatalf("resolving seeded area: %v", err)
	}

	_, out, err := callHandlerAs(t, "planner", s.proposeGoal, ProposeGoalInput{
		Area:       "learning",
		Title:      "Reach conversational Japanese",
		Milestones: []string{"Finish Genki I", "Finish Genki II"},
	})
	if err != nil {
		t.Fatalf("proposeGoal: %v", err)
	}
	if out.Goal == nil || out.Goal.ID == uuid.Nil {
		t.Fatal("proposeGoal returned no goal / zero ID")
	}

	var status, createdBy string
	var gotArea *uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`SELECT status, created_by, area_id FROM goals WHERE id = $1`, out.Goal.ID,
	).Scan(&status, &createdBy, &gotArea); err != nil {
		t.Fatalf("reading proposed goal: %v", err)
	}
	if status != "proposed" {
		t.Errorf("persisted status = %q, want %q", status, "proposed")
	}
	if createdBy != "planner" {
		t.Errorf("persisted created_by = %q, want %q", createdBy, "planner")
	}
	if gotArea == nil || *gotArea != areaID {
		t.Errorf("persisted area_id = %v, want %s (resolved from 'learning')", gotArea, areaID)
	}

	var titles []string
	rows, err := testPool.Query(t.Context(),
		`SELECT title FROM milestones WHERE goal_id = $1 ORDER BY position`, out.Goal.ID)
	if err != nil {
		t.Fatalf("reading milestones: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var title string
		if err := rows.Scan(&title); err != nil {
			t.Fatalf("scanning milestone: %v", err)
		}
		titles = append(titles, title)
	}
	if diff := cmp.Diff([]string{"Finish Genki I", "Finish Genki II"}, titles); diff != "" {
		t.Errorf("milestones mismatch (-want +got):\n%s", diff)
	}
}

// TestIntegration_ProposeGoal_UnderProposedArea proves the bundle case: a goal
// can be proposed under an area proposed earlier in the same flow (the
// include-proposed resolver). Both land inert.
func TestIntegration_ProposeGoal_UnderProposedArea(t *testing.T) {
	s := setupServer(t)
	t.Cleanup(func() { deleteProposedAreas(t) })

	if _, _, err := callHandlerAs(t, "planner", s.proposeArea, ProposeAreaInput{
		Name: "New Theme Studio",
	}); err != nil {
		t.Fatalf("proposeArea: %v", err)
	}

	_, out, err := callHandlerAs(t, "planner", s.proposeGoal, ProposeGoalInput{
		Area:  "new-theme-studio",
		Title: "First goal of the new theme",
	})
	if err != nil {
		t.Fatalf("proposeGoal under proposed area: %v", err)
	}

	var status string
	var areaStatus string
	if err := testPool.QueryRow(t.Context(),
		`SELECT g.status, a.status FROM goals g JOIN areas a ON a.id = g.area_id WHERE g.id = $1`,
		out.Goal.ID,
	).Scan(&status, &areaStatus); err != nil {
		t.Fatalf("reading proposed goal+area: %v", err)
	}
	if status != "proposed" {
		t.Errorf("goal status = %q, want proposed", status)
	}
	if areaStatus != "proposed" {
		t.Errorf("parent area status = %q, want proposed (bundle case)", areaStatus)
	}
}

// TestIntegration_ProposeGoal_Inert pins the inertness contract end-to-end: a
// proposed goal is absent from brief(morning).active_goals, while a sibling
// in_progress goal appears.
func TestIntegration_ProposeGoal_Inert(t *testing.T) {
	s := setupServer(t)

	if _, _, err := callHandlerAs(t, "planner", s.proposeGoal, ProposeGoalInput{
		Title: "Inert proposed goal",
	}); err != nil {
		t.Fatalf("proposeGoal: %v", err)
	}
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO goals (title, status) VALUES ('Active sibling goal', 'in_progress')`,
	); err != nil {
		t.Fatalf("seeding active goal: %v", err)
	}

	// Explicit sections=['goals'] — setupServer's learning-studio caller
	// otherwise defaults to ['tasks','hypotheses'] and active_goals stays empty
	// regardless of the goal's status.
	_, out, err := callHandler(t, s.brief, BriefInput{Mode: "morning", Sections: FlexStringSlice{"goals"}})
	if err != nil {
		t.Fatalf("brief(morning): %v", err)
	}
	if len(out.ActiveGoals) != 1 {
		t.Fatalf("active_goals len = %d, want 1 (proposed goal must be excluded): %+v",
			len(out.ActiveGoals), out.ActiveGoals)
	}
	if out.ActiveGoals[0].Title != "Active sibling goal" {
		t.Errorf("active_goals[0].Title = %q, want %q", out.ActiveGoals[0].Title, "Active sibling goal")
	}
}

// TestIntegration_ProposeGoal_UnknownAreaRejected asserts a non-empty area that
// matches no row is a clean caller error with nothing written.
func TestIntegration_ProposeGoal_UnknownAreaRejected(t *testing.T) {
	s := setupServer(t)

	if _, _, err := callHandlerAs(t, "planner", s.proposeGoal, ProposeGoalInput{
		Area:  "no-such-area",
		Title: "Goal under a missing area",
	}); err == nil {
		t.Error("proposeGoal with unknown area err = nil, want rejection")
	}

	var count int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM goals`,
	).Scan(&count); err != nil {
		t.Fatalf("counting goals: %v", err)
	}
	if count != 0 {
		t.Errorf("goal count = %d, want 0 (resolve failure must roll back)", count)
	}
}

// TestIntegration_ProposeGoal_BlankTitleRejected asserts the handler rejects a
// blank title and a blank milestone before any write.
func TestIntegration_ProposeGoal_BlankTitleRejected(t *testing.T) {
	s := setupServer(t)

	if _, _, err := callHandlerAs(t, "planner", s.proposeGoal, ProposeGoalInput{Title: "  "}); err == nil {
		t.Error("proposeGoal(blank title) err = nil, want rejection")
	}
	if _, _, err := callHandlerAs(t, "planner", s.proposeGoal, ProposeGoalInput{
		Title:      "Has a title",
		Milestones: []string{"ok", "  "},
	}); err == nil {
		t.Error("proposeGoal(blank milestone) err = nil, want rejection")
	}
}

// TestIntegration_ProposeGoal_RationalePersistsTriageOnly proves the rationale
// captured by propose_goal is (a) stored on the proposed row, (b) surfaced in
// the triage-list read, and (c) NOT leaked into the normal goal list. A sibling
// goal proposed without a rationale persists NULL (nil pointer), pinning the
// nullable→pointer mapping at both the store and triage-read layers.
func TestIntegration_ProposeGoal_RationalePersistsTriageOnly(t *testing.T) {
	s := setupServer(t)

	const rationale = "Recurring Japanese study sessions signal a real objective worth committing to."

	_, withRat, err := callHandlerAs(t, "planner", s.proposeGoal, ProposeGoalInput{
		Title:     "Reach conversational Japanese",
		Rationale: rationale,
	})
	if err != nil {
		t.Fatalf("proposeGoal(with rationale): %v", err)
	}
	_, noRat, err := callHandlerAs(t, "planner", s.proposeGoal, ProposeGoalInput{
		Title: "Goal with no rationale",
	})
	if err != nil {
		t.Fatalf("proposeGoal(no rationale): %v", err)
	}

	// (a) The proposed row stores the rationale verbatim; the omitted one is NULL.
	var stored *string
	if err := testPool.QueryRow(t.Context(),
		`SELECT proposal_rationale FROM goals WHERE id = $1`, withRat.Goal.ID,
	).Scan(&stored); err != nil {
		t.Fatalf("reading stored rationale: %v", err)
	}
	if stored == nil || *stored != rationale {
		t.Errorf("stored proposal_rationale = %v, want %q", stored, rationale)
	}
	var storedNil *string
	if err := testPool.QueryRow(t.Context(),
		`SELECT proposal_rationale FROM goals WHERE id = $1`, noRat.Goal.ID,
	).Scan(&storedNil); err != nil {
		t.Fatalf("reading omitted rationale: %v", err)
	}
	if storedNil != nil {
		t.Errorf("omitted proposal_rationale = %q, want NULL (nil)", *storedNil)
	}

	// (b) The triage-list read carries the rationale through to the UI, and the
	// omitted one stays nil.
	proposed, err := s.goals.ProposedGoals(t.Context())
	if err != nil {
		t.Fatalf("ProposedGoals: %v", err)
	}
	var gotRat, gotNil *string
	var found, foundNil bool
	for i := range proposed {
		switch proposed[i].ID {
		case withRat.Goal.ID:
			gotRat, found = proposed[i].ProposalRationale, true
		case noRat.Goal.ID:
			gotNil, foundNil = proposed[i].ProposalRationale, true
		}
	}
	if !found || !foundNil {
		t.Fatalf("triage list missing proposed goals (found=%v foundNil=%v)", found, foundNil)
	}
	if gotRat == nil || *gotRat != rationale {
		t.Errorf("triage ProposalRationale = %v, want %q", gotRat, rationale)
	}
	if gotNil != nil {
		t.Errorf("triage ProposalRationale (omitted) = %q, want nil", *gotNil)
	}

	// (c) The normal goal list never carries the rationale — even asked for
	// proposed rows explicitly, the active-list struct has no such field, so the
	// justification cannot appear in its serialized form.
	status := "proposed"
	list, err := s.goals.GoalsByOptionalStatus(t.Context(), &status)
	if err != nil {
		t.Fatalf("GoalsByOptionalStatus: %v", err)
	}
	blob, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshaling normal list: %v", err)
	}
	if strings.Contains(string(blob), rationale) {
		t.Errorf("normal goal list leaked proposal_rationale: %s", blob)
	}
}

// TestIntegration_ProposeArea_RationalePersistsTriageOnly is the area
// counterpart: propose_area's rationale is stored on the proposed row, surfaced
// in the triage list, and absent from the active-area selector (which excludes
// proposed areas entirely).
func TestIntegration_ProposeArea_RationalePersistsTriageOnly(t *testing.T) {
	s := setupServer(t)
	t.Cleanup(func() { deleteProposedAreas(t) })

	const rationale = "Backend craft keeps surfacing as a standing responsibility, not a one-off."

	_, out, err := callHandlerAs(t, "planner", s.proposeArea, ProposeAreaInput{
		Name:      "Backend Studio",
		Rationale: rationale,
	})
	if err != nil {
		t.Fatalf("proposeArea: %v", err)
	}

	// (a) Stored on the proposed row.
	var stored *string
	if err := testPool.QueryRow(t.Context(),
		`SELECT proposal_rationale FROM areas WHERE id = $1`, out.Area.ID,
	).Scan(&stored); err != nil {
		t.Fatalf("reading stored rationale: %v", err)
	}
	if stored == nil || *stored != rationale {
		t.Errorf("stored proposal_rationale = %v, want %q", stored, rationale)
	}

	// (b) Surfaced in the triage list.
	proposed, err := s.goals.ProposedAreas(t.Context())
	if err != nil {
		t.Fatalf("ProposedAreas: %v", err)
	}
	var got *string
	var found bool
	for i := range proposed {
		if proposed[i].ID == out.Area.ID {
			got, found = proposed[i].ProposalRationale, true
		}
	}
	if !found {
		t.Fatalf("triage list missing proposed area %s", out.Area.ID)
	}
	if got == nil || *got != rationale {
		t.Errorf("triage ProposalRationale = %v, want %q", got, rationale)
	}

	// (c) The active-area selector excludes proposed areas entirely, so the
	// rationale never reaches it.
	areas, err := s.goals.Areas(t.Context())
	if err != nil {
		t.Fatalf("Areas: %v", err)
	}
	blob, err := json.Marshal(areas)
	if err != nil {
		t.Fatalf("marshaling area selector: %v", err)
	}
	if strings.Contains(string(blob), rationale) {
		t.Errorf("active-area selector leaked proposal_rationale: %s", blob)
	}
}

// TestIntegration_ProposeProject_AsPlanner drives propose_project and asserts
// the inert-draft contract: the persisted row is status=proposed with
// created_by=the proposing agent and a slug derived from the name, and the
// proposed project is absent from the admin project list.
func TestIntegration_ProposeProject_AsPlanner(t *testing.T) {
	s := setupServer(t)

	_, out, err := callHandlerAs(t, "planner", s.proposeProject, ProposeProjectInput{
		Name:        "Koopa CLI",
		Description: "A command-line companion for the knowledge engine.",
		Rationale:   "Recurring requests for a terminal entry point.",
	})
	if err != nil {
		t.Fatalf("proposeProject: %v", err)
	}
	if out.Project == nil || out.Project.ID == uuid.Nil {
		t.Fatal("proposeProject returned no project / zero ID")
	}
	if out.Project.Slug != "koopa-cli" {
		t.Errorf("output slug = %q, want %q (derived from name)", out.Project.Slug, "koopa-cli")
	}
	if string(out.Project.Status) != "proposed" {
		t.Errorf("output status = %q, want %q", out.Project.Status, "proposed")
	}

	var status, createdBy string
	if err := testPool.QueryRow(t.Context(),
		`SELECT status, created_by FROM projects WHERE id = $1`, out.Project.ID,
	).Scan(&status, &createdBy); err != nil {
		t.Fatalf("reading proposed project: %v", err)
	}
	if status != "proposed" {
		t.Errorf("persisted status = %q, want %q (agent proposals land inert)", status, "proposed")
	}
	if createdBy != "planner" {
		t.Errorf("persisted created_by = %q, want %q", createdBy, "planner")
	}

	// Inert: absent from the admin project list.
	admin, err := s.projects.Projects(t.Context())
	if err != nil {
		t.Fatalf("Projects: %v", err)
	}
	for i := range admin {
		if admin[i].ID == out.Project.ID {
			t.Errorf("proposed project %s leaked into the admin project list", out.Project.ID)
		}
	}
}

// TestIntegration_ProposeProject_CallerGate asserts the registered-caller gate:
// the zero-privilege "unknown" fallback and a fabricated name are refused
// before any write.
func TestIntegration_ProposeProject_CallerGate(t *testing.T) {
	s := setupServer(t)

	for _, caller := range []string{"unknown", "fabricated-agent"} {
		_, _, err := callHandlerAs(t, caller, s.proposeProject, ProposeProjectInput{Name: "Should Never Persist"})
		if err == nil {
			t.Errorf("proposeProject as %q err = nil, want registered-caller refusal", caller)
		}
	}

	var count int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM projects WHERE status = 'proposed'`,
	).Scan(&count); err != nil {
		t.Fatalf("counting proposed projects: %v", err)
	}
	if count != 0 {
		t.Errorf("proposed project count = %d, want 0 (gate must precede any write)", count)
	}
}

// TestIntegration_ProposeProject_BlankNameRejected asserts the handler rejects a
// blank or non-sluggable name before any write.
func TestIntegration_ProposeProject_BlankNameRejected(t *testing.T) {
	s := setupServer(t)

	for _, name := range []string{"", "   ", "!!!"} {
		if _, _, err := callHandlerAs(t, "planner", s.proposeProject, ProposeProjectInput{Name: name}); err == nil {
			t.Errorf("proposeProject(name=%q) err = nil, want rejection", name)
		}
	}
}

// TestIntegration_ProposeProject_CaptureThenActivate proves the capture↔proposed
// ordering: capture_inbox links a todo to a still-proposed project by slug, and
// activating the project (a status flip) leaves the link intact — the todo
// auto-associates with the now-active project, no re-link needed.
func TestIntegration_ProposeProject_CaptureThenActivate(t *testing.T) {
	s := setupServer(t)

	_, proposed, err := callHandlerAs(t, "planner", s.proposeProject, ProposeProjectInput{Name: "Ordering Project"})
	if err != nil {
		t.Fatalf("proposeProject: %v", err)
	}

	_, captured, err := callHandlerAs(t, "planner", s.captureInbox, CaptureInboxInput{
		Title:   "todo for the proposed project",
		Project: "ordering-project",
	})
	if err != nil {
		t.Fatalf("captureInbox: %v", err)
	}
	if got := todoProjectID(t, captured.Task.ID); got == nil || *got != proposed.Project.ID {
		t.Fatalf("todo.project_id = %v at capture, want %s (resolveProjectID must match a proposed project)", got, proposed.Project.ID)
	}

	// Activation is a status flip; the todo's project_id is untouched.
	if _, err := s.projects.ActivateProject(t.Context(), proposed.Project.ID); err != nil {
		t.Fatalf("ActivateProject: %v", err)
	}
	if got := todoProjectID(t, captured.Task.ID); got == nil || *got != proposed.Project.ID {
		t.Errorf("todo.project_id = %v after activation, want %s (link must survive activation)", got, proposed.Project.ID)
	}
}

// TestIntegration_ProposeProject_CaptureThenReject proves the rejection branch:
// rejecting (hard-deleting) a proposed project a todo points at unlinks the todo
// (project_id SET NULL by the FK) while the todo itself survives unclassified.
func TestIntegration_ProposeProject_CaptureThenReject(t *testing.T) {
	s := setupServer(t)

	_, proposed, err := callHandlerAs(t, "planner", s.proposeProject, ProposeProjectInput{Name: "Doomed Project"})
	if err != nil {
		t.Fatalf("proposeProject: %v", err)
	}
	_, captured, err := callHandlerAs(t, "planner", s.captureInbox, CaptureInboxInput{
		Title:   "todo for the doomed project",
		Project: "doomed-project",
	})
	if err != nil {
		t.Fatalf("captureInbox: %v", err)
	}
	if got := todoProjectID(t, captured.Task.ID); got == nil || *got != proposed.Project.ID {
		t.Fatalf("todo.project_id = %v at capture, want %s", got, proposed.Project.ID)
	}

	if err := s.projects.RejectProject(t.Context(), proposed.Project.ID); err != nil {
		t.Fatalf("RejectProject: %v", err)
	}

	// The project is gone; the todo survives with project_id SET NULL.
	var exists bool
	if err := testPool.QueryRow(t.Context(),
		`SELECT EXISTS(SELECT 1 FROM todos WHERE id=$1)`, captured.Task.ID,
	).Scan(&exists); err != nil {
		t.Fatalf("checking todo survival: %v", err)
	}
	if !exists {
		t.Fatal("todo was deleted when its proposed project was rejected; want survive with project_id NULL")
	}
	if got := todoProjectID(t, captured.Task.ID); got != nil {
		t.Errorf("todo.project_id = %v after reject, want NULL", *got)
	}
}

// todoProjectID reads a todo's project_id, returning nil when it is NULL.
func todoProjectID(t *testing.T, todoID uuid.UUID) *uuid.UUID {
	t.Helper()
	var pid *uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`SELECT project_id FROM todos WHERE id=$1`, todoID,
	).Scan(&pid); err != nil {
		t.Fatalf("reading todo.project_id: %v", err)
	}
	return pid
}

// seedTodoForCreator inserts a todo with an explicit created_by, state, and
// created_at so the list_tasks readback tests can assert creator-scoping,
// state passthrough, and newest-first ordering deterministically. created_by
// must name a registered agent (todos.created_by FK → agents). A done state
// carries completed_at to satisfy chk_todo_completed_at_consistency. The raw
// INSERT fires trg_todos_audit with current_actor() falling back to 'system',
// harmless here — list_tasks reads todos.created_by, not the audit log.
func seedTodoForCreator(t *testing.T, createdBy, title, state string, createdAt time.Time) uuid.UUID {
	t.Helper()
	var completedAt *time.Time
	if state == "done" {
		completedAt = &createdAt
	}
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, state, created_by, created_at, completed_at)
		 VALUES ($1, $2::todo_state, $3, $4, $5)
		 RETURNING id`,
		title, state, createdBy, createdAt, completedAt,
	).Scan(&id); err != nil {
		t.Fatalf("seedTodoForCreator(created_by=%q, state=%q): %v", createdBy, state, err)
	}
	return id
}

// TestIntegration_ListTasks_ReturnsCallerTodos drives the happy path: a caller
// reads back exactly the todos it created, newest first, with state and
// created_by carried through. Two todos in distinct states (done newest, inbox
// older) pin both the ordering and the State passthrough.
func TestIntegration_ListTasks_ReturnsCallerTodos(t *testing.T) {
	s := setupServer(t)

	older := time.Now().Add(-2 * time.Hour)
	newer := time.Now().Add(-1 * time.Hour)
	oldID := seedTodoForCreator(t, "planner", "older proposal", "inbox", older)
	newID := seedTodoForCreator(t, "planner", "newer proposal", "done", newer)

	_, out, err := callHandlerAs(t, "planner", s.listTasks, ListTasksInput{})
	if err != nil {
		t.Fatalf("listTasks: %v", err)
	}

	want := []TaskListItem{
		{ID: newID.String(), Title: "newer proposal", State: "done", CreatedBy: "planner"},
		{ID: oldID.String(), Title: "older proposal", State: "inbox", CreatedBy: "planner"},
	}
	if diff := cmp.Diff(want, out.Tasks); diff != "" {
		t.Errorf("listTasks(planner) mismatch (-want +got):\n%s", diff)
	}
}

// TestIntegration_ListTasks_CallerGate asserts the registered-caller gate: the
// zero-privilege "unknown" fallback and a fabricated name are refused. Without
// the gate the handler would fall through to TodosByCreator and return an empty
// list with no error, so a nil error here means the gate is missing.
func TestIntegration_ListTasks_CallerGate(t *testing.T) {
	s := setupServer(t)

	for _, caller := range []string{"unknown", "fabricated-agent"} {
		if _, _, err := callHandlerAs(t, caller, s.listTasks, ListTasksInput{}); err == nil {
			t.Errorf("listTasks as %q err = nil, want registered-caller refusal", caller)
		}
	}
}

// TestIntegration_ListTasks_CallerScoped pins the privacy invariant: the list
// is scoped to the resolved caller, so caller A (planner) never sees caller B's
// (learning-studio) todos.
func TestIntegration_ListTasks_CallerScoped(t *testing.T) {
	s := setupServer(t)

	mineID := seedTodoForCreator(t, "planner", "planner todo", "inbox", time.Now())
	theirsID := seedTodoForCreator(t, "learning-studio", "studio todo", "inbox", time.Now())

	_, out, err := callHandlerAs(t, "planner", s.listTasks, ListTasksInput{})
	if err != nil {
		t.Fatalf("listTasks: %v", err)
	}

	var sawMine, sawTheirs bool
	for _, ti := range out.Tasks {
		switch ti.ID {
		case mineID.String():
			sawMine = true
		case theirsID.String():
			sawTheirs = true
		}
		if ti.CreatedBy != "planner" {
			t.Errorf("listTasks(planner) returned created_by=%q, want planner-scoped only", ti.CreatedBy)
		}
	}
	if !sawMine {
		t.Errorf("listTasks(planner) missing the caller's own todo %s", mineID)
	}
	if sawTheirs {
		t.Errorf("listTasks(planner) leaked another agent's todo %s (caller-scoping violated)", theirsID)
	}
}

// TestIntegration_BriefReflection_CountsFromTodoState pins that brief(reflection)
// derives completed/deferred/planned from each planned todo's CURRENT state, not
// the daily_plan_item.status column (which has no write path — it stays 'planned'
// forever, so the old switch reported 0% completion regardless of reality).
func TestIntegration_BriefReflection_CountsFromTodoState(t *testing.T) {
	s := setupServer(t)

	const planDate = "2026-05-27"
	// A done todo needs completed_at set (chk_todo_completed_at_consistency);
	// seedTodoState only covers non-terminal states.
	done := func(title string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := testPool.QueryRow(t.Context(),
			`INSERT INTO todos (title, state, completed_at) VALUES ($1, 'done', now()) RETURNING id`,
			title).Scan(&id); err != nil {
			t.Fatalf("seeding done todo %q: %v", title, err)
		}
		return id
	}
	ids := []uuid.UUID{
		done("reflection-done-A"),
		done("reflection-done-B"),
		seedTodoState(t, "reflection-someday", "someday"),
		seedTodoState(t, "reflection-pending", "todo"),
	}
	for pos, id := range ids {
		if _, err := testPool.Exec(t.Context(),
			`INSERT INTO daily_plan_items (plan_date, todo_id, selected_by, position)
			 VALUES ($1::date, $2, 'human', $3)`,
			planDate, id, pos); err != nil {
			t.Fatalf("seeding plan item %d: %v", pos, err)
		}
	}

	date := planDate
	_, out, err := callHandler(t, s.brief, BriefInput{Mode: "reflection", Date: &date})
	if err != nil {
		t.Fatalf("brief(reflection): %v", err)
	}

	if out.CompletedCount != 2 {
		t.Errorf("CompletedCount = %d, want 2 (two done todos)", out.CompletedCount)
	}
	if out.DeferredCount != 1 {
		t.Errorf("DeferredCount = %d, want 1 (one someday todo)", out.DeferredCount)
	}
	if out.PlannedCount != 1 {
		t.Errorf("PlannedCount = %d, want 1 (one still-todo todo)", out.PlannedCount)
	}
	if out.CompletionRate != 0.5 {
		t.Errorf("CompletionRate = %v, want 0.5 (2 of 4)", out.CompletionRate)
	}
}
