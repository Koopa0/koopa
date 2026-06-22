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
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/mcp/ops"
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
// wired to the shared test pool. callerAgent is set to planner — a
// registered claude-cowork daily-driver — so every activity_events row in a
// happy-path test should carry that actor.
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
		WithCallerAgent("planner"),
	)
}

// truncateApplicationTables clears every table an MCP handler can write to
// while preserving seed data from 002 (areas, topics, feeds,
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
		"readings",
		"songs",
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

// TestIntegration_ColdStart_CaptureInbox was a cold-start failure mode in the
// audit: activity_events_actor_fkey violation because koopa.actor was unset and
// the fallback 'system' wasn't in agents. With the registry seed and the
// withActorTx wrapper in place, this must write both the todo and the audit row
// with actor = planner (the configured caller).
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

	if got := activityActorFor(t, "todo", out.Task.ID); got != "planner" {
		t.Errorf("activity_events.actor = %q, want %q (koopa.actor propagation)", got, "planner")
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

// assertSearchResultShape checks the stable required fields of a single result
// envelope item. Does not assert order or relevance. The corpus is now
// {content, reading, song}: content hits carry a slug + content_type; reading
// and song hits link to the parent shelf row by id/title and carry no slug
// (those tables have none) and no content_type.
func assertSearchResultShape(t *testing.T, r *SearchKnowledgeResult) {
	t.Helper()
	if r.ID == "" {
		t.Errorf("result.id empty: %+v", r)
	}
	if r.Title == "" {
		t.Errorf("result.title empty: %+v", r)
	}
	if r.CreatedAt == "" {
		t.Errorf("result.created_at empty: %+v", r)
	} else if _, err := time.Parse(time.RFC3339, r.CreatedAt); err != nil {
		t.Errorf("result.created_at %q not RFC3339: %v", r.CreatedAt, err)
	}
	switch r.SourceType {
	case SourceTypeContent:
		if r.Slug == "" {
			t.Errorf("content result missing slug: %+v", r)
		}
		if r.ContentType == "" {
			t.Errorf("content result missing content_type: %+v", r)
		}
	case SourceTypeReading, SourceTypeSong:
		if r.Excerpt == "" {
			t.Errorf("%s result missing excerpt (matched text): %+v", r.SourceType, r)
		}
	default:
		t.Errorf("unknown source_type %q (corpus is content, reading, song)", r.SourceType)
	}
}

// --- corpus inclusion ---

// TestIntegration_SearchKnowledge_CorpusInclusion seeds one content row matching
// a unique term and asserts the content corpus surfaces it with a stable result
// shape and the correct source_type. No order assertion.
func TestIntegration_SearchKnowledge_CorpusInclusion(t *testing.T) {
	s := setupServer(t)
	const term = "zqxincl"
	cID := seedSearchContent(t, "sk-incl-content", term, "draft")

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

	var sawContent bool
	for i := range out.Results {
		r := &out.Results[i]
		assertSearchResultShape(t, r)
		if r.ID == cID.String() {
			sawContent = true
			if r.SourceType != SourceTypeContent {
				t.Errorf("content row source_type = %q, want %q", r.SourceType, SourceTypeContent)
			}
		}
	}
	if !sawContent {
		t.Error("content corpus not represented in results (expected the seeded content row)")
	}
}

// --- corpus exclusion ---

// TestIntegration_SearchKnowledge_CorpusExclusion seeds one in-corpus content
// row and asserts only the content source type surfaces in search_knowledge
// results — no non-content entity leaks. The in-corpus content row presence
// guards against a vacuous pass (a non-matching term would make the exclusion
// trivially true).
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
		if r.SourceType != SourceTypeContent {
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
// (1) a valid content_type narrows to the content branch;
// (2) a valid-but-unmatched content_type yields empty (no error);
// (3) an UNKNOWN content_type is rejected with a validation error (Track 1I
//
//	decision — strict enum validation, consistent with create_content; replaces
//	the Track 1G silent-empty characterization).
func TestIntegration_SearchKnowledge_ContentTypeFilter(t *testing.T) {
	s := setupServer(t)
	const term = "zqxctf"
	seedSearchContent(t, "sk-ctf-content", term, "draft") // type=article

	t.Run("article narrows to content", func(t *testing.T) {
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
		// truncates contents per test, and every term in this file uses a
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
// tested (TestSelectSources). It seeds one content row matching the term and
// asserts source_types=[content] returns only the content row, and that any
// token outside {content} — including the now-retired "note" corpus and an
// arbitrary "bookmark" — is rejected at the handler with an error (not a silent
// empty success).
func TestIntegration_SearchKnowledge_SourceTypesEndToEnd(t *testing.T) {
	s := setupServer(t)
	const term = "zqxsrc"
	cID := seedSearchContent(t, "sk-src-content", term, "draft")

	t.Run("content only returns content", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, SourceTypes: []string{SourceTypeContent}})
		if err != nil {
			t.Fatalf("source_types=[content]: %v", err)
		}
		if len(out.Results) != 1 || out.Results[0].ID != cID.String() {
			t.Errorf("source_types=[content] = %d results, want exactly the content row %s", len(out.Results), cID)
		}
	})

	t.Run("unsupported source_type rejected, not silent empty", func(t *testing.T) {
		// "note" is a retired corpus token, "bookmark" was never a corpus —
		// both must be rejected so "unsupported filter" stays distinguishable
		// from "no match".
		for _, st := range []string{"note", "bookmark"} {
			_, _, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, SourceTypes: []string{st}})
			if err == nil {
				t.Errorf("source_types=[%q] must error, not return empty success", st)
				continue
			}
			if !strings.Contains(err.Error(), "unsupported source_type") {
				t.Errorf("source_types=[%q] error = %q, want containing %q", st, err, "unsupported source_type")
			}
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

	// Explicit sections=['goals'] narrows the morning brief to active_goals so
	// this test asserts only the goals projection (the caller would otherwise
	// get every section).
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
// (codex) todos.
func TestIntegration_ListTasks_CallerScoped(t *testing.T) {
	s := setupServer(t)

	mineID := seedTodoForCreator(t, "planner", "planner todo", "inbox", time.Now())
	theirsID := seedTodoForCreator(t, "codex", "codex todo", "inbox", time.Now())

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

// TestIntegration_ResolveTask_ClosesOwnTodo pins the write half of the readback
// loop: an agent moves a todo IT created to a terminal state and the row's state
// changes in the DB.
func TestIntegration_ResolveTask_ClosesOwnTodo(t *testing.T) {
	s := setupServer(t)

	id := seedTodoForCreator(t, "planner", "captured idea", "inbox", time.Now())

	_, out, err := callHandlerAs(t, "planner", s.resolveTask, ResolveTaskInput{ID: id.String(), State: "dismissed"})
	if err != nil {
		t.Fatalf("resolveTask: %v", err)
	}
	want := ResolveTaskOutput{ID: id.String(), State: "dismissed", OK: true}
	if diff := cmp.Diff(want, out); diff != "" {
		t.Errorf("resolveTask mismatch (-want +got):\n%s", diff)
	}

	var state string
	if err := testPool.QueryRow(t.Context(), "SELECT state FROM todos WHERE id = $1", id).Scan(&state); err != nil {
		t.Fatalf("reading back todo state: %v", err)
	}
	if state != "dismissed" {
		t.Errorf("todo %s state = %q, want dismissed", id, state)
	}
}

// TestIntegration_ResolveTask_InvalidState rejects any state outside the
// done/archived/dismissed terminal set without mutating.
func TestIntegration_ResolveTask_InvalidState(t *testing.T) {
	s := setupServer(t)
	id := seedTodoForCreator(t, "planner", "captured idea", "inbox", time.Now())

	if _, _, err := callHandlerAs(t, "planner", s.resolveTask, ResolveTaskInput{ID: id.String(), State: "todo"}); err == nil {
		t.Error("resolveTask(state=todo) err = nil, want invalid-state rejection")
	}
}

// TestIntegration_ResolveTask_CallerGate refuses the zero-privilege fallback and
// a fabricated caller — the registered-caller gate must run before any write.
func TestIntegration_ResolveTask_CallerGate(t *testing.T) {
	s := setupServer(t)
	id := seedTodoForCreator(t, "planner", "captured idea", "inbox", time.Now())

	for _, caller := range []string{"unknown", "fabricated-agent"} {
		if _, _, err := callHandlerAs(t, caller, s.resolveTask, ResolveTaskInput{ID: id.String(), State: "done"}); err == nil {
			t.Errorf("resolveTask as %q err = nil, want registered-caller refusal", caller)
		}
	}
}

// TestIntegration_ResolveTask_CallerScoped pins the privacy invariant: caller A
// cannot resolve a todo created by caller B — it returns not-found and the row
// is left untouched, never a cross-creator mutation.
func TestIntegration_ResolveTask_CallerScoped(t *testing.T) {
	s := setupServer(t)
	theirs := seedTodoForCreator(t, "codex", "codex todo", "inbox", time.Now())

	if _, _, err := callHandlerAs(t, "planner", s.resolveTask, ResolveTaskInput{ID: theirs.String(), State: "dismissed"}); err == nil {
		t.Error("resolveTask(planner) on codex's todo err = nil, want not-found (caller-scoping)")
	}

	var state string
	if err := testPool.QueryRow(t.Context(), "SELECT state FROM todos WHERE id = $1", theirs).Scan(&state); err != nil {
		t.Fatalf("reading back todo state: %v", err)
	}
	if state != "inbox" {
		t.Errorf("codex todo %s state = %q after cross-creator resolve, want unchanged inbox", theirs, state)
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

// --- reading shelf read tools (list_readings / get_reading) ---

// seedReading inserts a book directly. The readings tables carry no audit
// trigger and no created_by FK (single human writer, by design — see the
// readings table comment in 001_initial.up.sql), so a raw INSERT is the
// whole story. A status outside the four shelf states fails the CHECK, which
// is the intended guard.
func seedReading(t *testing.T, title, author, status string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO readings (title, author, status) VALUES ($1, $2, $3) RETURNING id`,
		title, author, status,
	).Scan(&id); err != nil {
		t.Fatalf("seedReading(%q, status=%q): %v", title, status, err)
	}
	return id
}

// seedReflection inserts a diary entry under a reading with an explicit
// entry_date so thread ordering is deterministic.
func seedReflection(t *testing.T, readingID uuid.UUID, entryDate, body string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO reading_reflections (reading_id, entry_date, body)
		 VALUES ($1, $2::date, $3) RETURNING id`,
		readingID, entryDate, body,
	).Scan(&id); err != nil {
		t.Fatalf("seedReflection(reading=%s, %s, %q): %v", readingID, entryDate, body, err)
	}
	return id
}

// seedSong inserts a song directly. Like readings, the songs tables carry no
// audit trigger and no created_by FK (single human writer). translation is the
// owner's working-language layer the FTS search_vector weights, so a seed sets
// it to drive lexical matches.
func seedSong(t *testing.T, titleJa, album, translation string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO songs (title_ja, album, translation) VALUES ($1, $2, $3) RETURNING id`,
		titleJa, album, translation,
	).Scan(&id); err != nil {
		t.Fatalf("seedSong(%q): %v", titleJa, err)
	}
	return id
}

// seedSongReflection inserts a reflection under a song with an explicit
// entry_date.
func seedSongReflection(t *testing.T, songID uuid.UUID, entryDate, body string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO song_reflections (song_id, entry_date, body)
		 VALUES ($1, $2::date, $3) RETURNING id`,
		songID, entryDate, body,
	).Scan(&id); err != nil {
		t.Fatalf("seedSongReflection(song=%s, %s, %q): %v", songID, entryDate, body, err)
	}
	return id
}

// --- search_knowledge: reading + song corpora (FTS path) ---

// TestIntegration_SearchKnowledge_ReadingSongCorpora is the end-to-end proof
// that the reading shelf and the ヨルシカ song shelf joined the search corpus.
// Embeddings need GEMINI_API_KEY, so this asserts the FTS path only (the
// server here has no embedder, so the semantic branch is skipped) plus the
// source_types narrowing. It pins the load-bearing semantics:
//   - a reading SHELF hit surfaces with source_type=reading, linking to the book;
//   - a reading REFLECTION hit folds under its parent book (same source_type,
//     parent id, excerpt = the diary body) — NOT a separate reflection corpus;
//   - the same for the song shelf + reflections (source_type=song);
//   - source_types narrows the corpus, and the default searches all three.
func TestIntegration_SearchKnowledge_ReadingSongCorpora(t *testing.T) {
	s := setupServer(t)

	// A term unique to each matchable surface so a hit is unambiguous.
	bookID := seedReading(t, "Norwegian Wood", "Murakami", "finished")
	const reflTerm = "zqxreflread"
	seedReflection(t, bookID, "2026-05-10", "today the "+reflTerm+" theme finally landed")

	songID := seedSong(t, "花に亡霊", "創作", "a song about loneliness")
	const songReflTerm = "zqxreflsong"
	seedSongReflection(t, songID, "2026-05-11", "the bridge captures "+songReflTerm+" perfectly")

	t.Run("reading reflection hit folds under parent book", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: reflTerm})
		if err != nil {
			t.Fatalf("searchKnowledge(%q): %v", reflTerm, err)
		}
		r := findResultByID(t, out.Results, bookID.String())
		if r == nil {
			t.Fatalf("reflection term %q did not surface parent book %s; got %d results", reflTerm, bookID, len(out.Results))
		}
		if r.SourceType != SourceTypeReading {
			t.Errorf("source_type = %q, want %q (reflection folds under reading)", r.SourceType, SourceTypeReading)
		}
		if r.Title != "Norwegian Wood" {
			t.Errorf("title = %q, want the parent book title", r.Title)
		}
		if !strings.Contains(r.Excerpt, reflTerm) {
			t.Errorf("excerpt = %q, want the matched diary body containing %q", r.Excerpt, reflTerm)
		}
		assertSearchResultShape(t, r)
	})

	t.Run("song reflection hit folds under parent song", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: songReflTerm})
		if err != nil {
			t.Fatalf("searchKnowledge(%q): %v", songReflTerm, err)
		}
		r := findResultByID(t, out.Results, songID.String())
		if r == nil {
			t.Fatalf("reflection term %q did not surface parent song %s; got %d results", songReflTerm, songID, len(out.Results))
		}
		if r.SourceType != SourceTypeSong {
			t.Errorf("source_type = %q, want %q (reflection folds under song)", r.SourceType, SourceTypeSong)
		}
		if !strings.Contains(r.Excerpt, songReflTerm) {
			t.Errorf("excerpt = %q, want the matched reflection body containing %q", r.Excerpt, songReflTerm)
		}
		assertSearchResultShape(t, r)
	})

	t.Run("reading shelf hit surfaces by title", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: "Murakami"})
		if err != nil {
			t.Fatalf("searchKnowledge(Murakami): %v", err)
		}
		r := findResultByID(t, out.Results, bookID.String())
		if r == nil {
			t.Fatalf("author term did not surface the book %s (search_vector weights author B)", bookID)
		}
		if r.SourceType != SourceTypeReading {
			t.Errorf("source_type = %q, want %q", r.SourceType, SourceTypeReading)
		}
	})

	t.Run("song shelf hit via translation", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: "loneliness"})
		if err != nil {
			t.Fatalf("searchKnowledge(loneliness): %v", err)
		}
		r := findResultByID(t, out.Results, songID.String())
		if r == nil {
			t.Fatalf("translation term did not surface the song %s (search_vector weights translation C)", songID)
		}
		if r.SourceType != SourceTypeSong {
			t.Errorf("source_type = %q, want %q", r.SourceType, SourceTypeSong)
		}
	})

	t.Run("source_types narrows to reading only", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: reflTerm, SourceTypes: []string{SourceTypeReading}})
		if err != nil {
			t.Fatalf("searchKnowledge(reading-only): %v", err)
		}
		if diff := cmp.Diff([]string{SourceTypeReading}, out.SearchedCorpus); diff != "" {
			t.Errorf("searched_corpus mismatch (-want +got):\n%s", diff)
		}
		for i := range out.Results {
			if out.Results[i].SourceType != SourceTypeReading {
				t.Errorf("result %d source_type = %q, want reading-only", i, out.Results[i].SourceType)
			}
		}
	})

	t.Run("source_types=song excludes the reading hit", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: reflTerm, SourceTypes: []string{SourceTypeSong}})
		if err != nil {
			t.Fatalf("searchKnowledge(song-only): %v", err)
		}
		if r := findResultByID(t, out.Results, bookID.String()); r != nil {
			t.Errorf("song-only search returned the reading hit %s — corpus narrowing failed", bookID)
		}
	})

	t.Run("default corpus is all three", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: reflTerm})
		if err != nil {
			t.Fatalf("searchKnowledge(default): %v", err)
		}
		want := []string{SourceTypeContent, SourceTypeReading, SourceTypeSong}
		if diff := cmp.Diff(want, out.SearchedCorpus); diff != "" {
			t.Errorf("default searched_corpus mismatch (-want +got):\n%s", diff)
		}
	})
}

// findResultByID returns the first result with the given id, or nil. Order- and
// rank-agnostic so this stays inside the tier-1 contract (presence/absence
// only, no ranking metric).
func findResultByID(t *testing.T, results []SearchKnowledgeResult, id string) *SearchKnowledgeResult {
	t.Helper()
	for i := range results {
		if results[i].ID == id {
			return &results[i]
		}
	}
	return nil
}

// TestIntegration_ListReadings_ReturnsShelf drives the happy path: every
// seeded book comes back, newest-updated first, with goal_id null when the
// book serves no goal. Without the goal_id column wired through, the GoalID
// field would be absent or wrong here.
func TestIntegration_ListReadings_ReturnsShelf(t *testing.T) {
	s := setupServer(t)

	wantID := seedReading(t, "Wishlist Book", "A. Author", "want_to_read")
	readingID := seedReading(t, "Current Book", "", "reading")

	_, out, err := callHandlerAs(t, "planner", s.listReadings, ListReadingsInput{})
	if err != nil {
		t.Fatalf("listReadings: %v", err)
	}

	got := make(map[string]ReadingListItem, len(out.Readings))
	for _, it := range out.Readings {
		got[it.ID] = it
	}
	if len(got) != 2 {
		t.Fatalf("listReadings returned %d books, want 2", len(out.Readings))
	}
	if w := got[wantID.String()]; w.Title != "Wishlist Book" || w.Author != "A. Author" || w.Status != "want_to_read" || w.GoalID != nil {
		t.Errorf("listReadings[%s] = %+v, want title/author/status set and goal_id nil", wantID, w)
	}
	if r := got[readingID.String()]; r.Status != "reading" || r.Author != "" {
		t.Errorf("listReadings[%s] = %+v, want status=reading author empty", readingID, r)
	}
}

// TestIntegration_ListReadings_StatusFilter narrows the shelf to one state and
// rejects a non-empty invalid status without touching the store. A handler
// that forwarded the bad value to the DB would surface a 500-shaped error
// (or return everything); the clean rejection here pins the enum guard.
func TestIntegration_ListReadings_StatusFilter(t *testing.T) {
	s := setupServer(t)

	seedReading(t, "Wishlist", "", "want_to_read")
	currentID := seedReading(t, "Current", "", "reading")
	seedReading(t, "Done", "", "finished")

	_, out, err := callHandlerAs(t, "planner", s.listReadings, ListReadingsInput{Status: "reading"})
	if err != nil {
		t.Fatalf("listReadings(status=reading): %v", err)
	}
	if len(out.Readings) != 1 || out.Readings[0].ID != currentID.String() {
		t.Errorf("listReadings(status=reading) = %d rows, want exactly the reading-status book %s", len(out.Readings), currentID)
	}

	if _, _, err := callHandlerAs(t, "planner", s.listReadings, ListReadingsInput{Status: "bogus"}); err == nil {
		t.Error("listReadings(status=bogus) err = nil, want invalid-status rejection")
	}
}

// TestIntegration_ListReadings_CallerGate refuses the zero-privilege fallback
// and a fabricated caller — the private shelf must not be readable without a
// known identity.
func TestIntegration_ListReadings_CallerGate(t *testing.T) {
	s := setupServer(t)
	seedReading(t, "Private Book", "", "reading")

	for _, caller := range []string{"unknown", "fabricated-agent"} {
		if _, _, err := callHandlerAs(t, caller, s.listReadings, ListReadingsInput{}); err == nil {
			t.Errorf("listReadings as %q err = nil, want registered-caller refusal", caller)
		}
	}
}

// TestIntegration_GetReading_ReturnsBookAndThread pins the detail path: the
// book plus its diary in entry_date order (created_at tiebreak), the two
// same-day entries exercising the tiebreak. A missing/DESC ORDER BY or a
// dropped reflection fails the body-order assertion.
func TestIntegration_GetReading_ReturnsBookAndThread(t *testing.T) {
	s := setupServer(t)

	bookID := seedReading(t, "Threaded Book", "T. Writer", "reading")
	// Inserted out of diary order; the two 06-01 entries pin the created_at
	// tiebreak (insertion order).
	seedReflection(t, bookID, "2026-06-02", "second day")
	seedReflection(t, bookID, "2026-06-01", "first day")
	seedReflection(t, bookID, "2026-06-01", "first day, later thought")

	_, out, err := callHandlerAs(t, "planner", s.getReading, GetReadingInput{ID: bookID.String()})
	if err != nil {
		t.Fatalf("getReading: %v", err)
	}

	if out.Reading.ID != bookID.String() || out.Reading.Title != "Threaded Book" || out.Reading.Author != "T. Writer" {
		t.Errorf("getReading.Reading = %+v, want the seeded book", out.Reading)
	}
	if out.Reading.GoalID != nil {
		t.Errorf("getReading.Reading.GoalID = %v, want nil (no goal linked)", out.Reading.GoalID)
	}
	gotBodies := make([]string, len(out.Reflections))
	for i, r := range out.Reflections {
		gotBodies[i] = r.Body
	}
	wantBodies := []string{"first day", "first day, later thought", "second day"}
	if diff := cmp.Diff(wantBodies, gotBodies); diff != "" {
		t.Errorf("getReading reflection thread order mismatch (-want +got):\n%s", diff)
	}
}

// TestIntegration_GetReading_UnknownID maps a missing book to a clean
// not-found error, never a 500-shaped store error.
func TestIntegration_GetReading_UnknownID(t *testing.T) {
	s := setupServer(t)

	if _, _, err := callHandlerAs(t, "planner", s.getReading, GetReadingInput{ID: uuid.New().String()}); err == nil {
		t.Error("getReading(unknown id) err = nil, want not-found")
	}
}

// TestIntegration_GetReading_CallerGate refuses the zero-privilege fallback
// and a fabricated caller for the detail path too.
func TestIntegration_GetReading_CallerGate(t *testing.T) {
	s := setupServer(t)
	bookID := seedReading(t, "Private Book", "", "reading")

	for _, caller := range []string{"unknown", "fabricated-agent"} {
		if _, _, err := callHandlerAs(t, caller, s.getReading, GetReadingInput{ID: bookID.String()}); err == nil {
			t.Errorf("getReading as %q err = nil, want registered-caller refusal", caller)
		}
	}
}

// --- project_progress (read-only PARA momentum/stalled) ---
//
// These tests pin the load-bearing semantics: the HUMAN-ONLY activity
// filter (agent/system actors must not count as progress), the stalled
// threshold (2× cadence + open next action), and area neglect (>14 days
// with no human activity anywhere under the area). activity_events rows are
// seeded DIRECTLY with controlled occurred_at + actor — the only way to pin
// a timestamp, since the audit trigger stamps now(). A direct INSERT is a
// convention violation for application code, never the schema (the table
// comment says so), and is exactly what a fixture needs here.

// seedProgressProject inserts an active project with an expected cadence,
// optionally linked to a goal and an area, and returns its id.
func seedProgressProject(t *testing.T, slug, title, cadence string, goalID, areaID *uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO projects (slug, title, status, expected_cadence, goal_id, area_id)
		 VALUES ($1, $2, 'in_progress', $3, $4, $5) RETURNING id`,
		slug, title, cadence, goalID, areaID,
	).Scan(&id); err != nil {
		t.Fatalf("seedProgressProject(%q, cadence=%s): %v", slug, cadence, err)
	}
	return id
}

// seedProgressGoal inserts an in_progress goal and returns its id.
func seedProgressGoal(t *testing.T, title string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO goals (title, status) VALUES ($1, 'in_progress') RETURNING id`,
		title,
	).Scan(&id); err != nil {
		t.Fatalf("seedProgressGoal(%q): %v", title, err)
	}
	return id
}

// seedProgressMilestone inserts a milestone under a goal, completed when
// completed is true.
func seedProgressMilestone(t *testing.T, goalID uuid.UUID, title string, position int, completed bool) {
	t.Helper()
	var completedAt *time.Time
	if completed {
		now := time.Now()
		completedAt = &now
	}
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO milestones (goal_id, title, position, completed_at)
		 VALUES ($1, $2, $3, $4)`,
		goalID, title, position, completedAt,
	); err != nil {
		t.Fatalf("seedProgressMilestone(goal=%s, %q): %v", goalID, title, err)
	}
}

// seedProgressTodo inserts a todo linked to a project in the given state.
func seedProgressTodo(t *testing.T, projectID uuid.UUID, title, state string) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO todos (title, state, project_id) VALUES ($1, $2::todo_state, $3)`,
		title, state, projectID,
	); err != nil {
		t.Fatalf("seedProgressTodo(project=%s, %q, %s): %v", projectID, title, state, err)
	}
}

// areaIDBySlug resolves a seeded/migration area slug to its id.
func areaIDBySlug(t *testing.T, slug string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`SELECT id FROM areas WHERE slug = $1`, slug,
	).Scan(&id); err != nil {
		t.Fatalf("areaIDBySlug(%q): %v", slug, err)
	}
	return id
}

// seedActivityEvent inserts an activity_events row directly with a controlled
// actor and occurred_at. Fixture-only: the audit trigger would stamp now()
// and current_actor(), which a momentum test cannot control. project_id is
// what project_progress scopes its human-activity read to.
func seedActivityEvent(t *testing.T, projectID uuid.UUID, actor string, occurredAt time.Time) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO activity_events (entity_type, entity_id, change_kind, project_id, actor, occurred_at)
		 VALUES ('project', $1, 'updated', $1, $2, $3)`,
		projectID, actor, occurredAt,
	); err != nil {
		t.Fatalf("seedActivityEvent(project=%s, actor=%s): %v", projectID, actor, err)
	}
}

// TestIntegration_ProjectProgress_HumanOnlyAndStalled pins the two core
// rules at once. A project whose ONLY recent activity is by a non-human
// actor (planner) must read as stalled — the agent event does not count —
// while a sibling with a recent HUMAN event on the same cadence must not.
// A bug that counted any-actor activity (e.g. trusting projects.last_activity_at
// or dropping the actor='human' filter) would flip the stalled verdict on
// the agent-only project to false and fail this test.
func TestIntegration_ProjectProgress_HumanOnlyAndStalled(t *testing.T) {
	s := setupServer(t)

	goalID := seedProgressGoal(t, "Ship the engine")
	seedProgressMilestone(t, goalID, "API layer", 0, true)     // done
	seedProgressMilestone(t, goalID, "Search layer", 1, false) // open

	// Agent-only project: human touched it 30 days ago (well past the
	// daily 2-day threshold); a planner event yesterday must NOT rescue it.
	agentOnly := seedProgressProject(t, "agent-only", "Agent Only", "daily", &goalID, nil)
	seedProgressTodo(t, agentOnly, "wire search", "todo") // open next action
	seedActivityEvent(t, agentOnly, "human", time.Now().AddDate(0, 0, -30))
	seedActivityEvent(t, agentOnly, "planner", time.Now().AddDate(0, 0, -1))

	// Fresh-human project: human event yesterday, daily cadence → not stalled.
	fresh := seedProgressProject(t, "fresh-human", "Fresh Human", "daily", &goalID, nil)
	seedProgressTodo(t, fresh, "polish", "todo")
	seedActivityEvent(t, fresh, "human", time.Now().AddDate(0, 0, -1))

	// To-plan project: stale human activity but NO open next action → 待規劃,
	// never stalled.
	toPlan := seedProgressProject(t, "to-plan", "To Plan", "daily", nil, nil)
	seedActivityEvent(t, toPlan, "human", time.Now().AddDate(0, 0, -30))

	_, out, err := callHandlerAs(t, "planner", s.projectProgress, ProjectProgressInput{})
	if err != nil {
		t.Fatalf("projectProgress: %v", err)
	}

	got := make(map[string]ProgressProject, len(out.Projects))
	for _, p := range out.Projects {
		got[p.Slug] = p
	}
	if len(got) != 3 {
		t.Fatalf("projectProgress returned %d projects, want 3: %+v", len(out.Projects), out.Projects)
	}

	if p := got["agent-only"]; !p.Stalled {
		t.Errorf("agent-only stalled = false, want true (planner event must not count as human progress); days_since=%v", p.DaysSinceHumanAction)
	}
	if p := got["agent-only"]; p.DaysSinceHumanAction == nil || *p.DaysSinceHumanAction < 29 {
		t.Errorf("agent-only days_since_human_activity = %v, want ~30 (human event, not the day-old planner one)", p.DaysSinceHumanAction)
	}
	if p := got["fresh-human"]; p.Stalled {
		t.Errorf("fresh-human stalled = true, want false (human active yesterday on daily cadence)")
	}
	if p := got["to-plan"]; p.Stalled {
		t.Errorf("to-plan stalled = true, want false (no open next action → 待規劃)")
	}
	if p := got["to-plan"]; p.OpenNextAction {
		t.Errorf("to-plan open_next_action = true, want false")
	}
	if p := got["agent-only"]; !p.OpenNextAction {
		t.Errorf("agent-only open_next_action = false, want true (has an open todo)")
	}

	// Goal rollup: 1 done / 2 total milestones, 2 candidate projects under
	// the goal, 1 of them stalled (agent-only).
	var goalRollup *ProgressGoal
	for i := range out.Goals {
		if out.Goals[i].ID == goalID.String() {
			goalRollup = &out.Goals[i]
		}
	}
	if goalRollup == nil {
		t.Fatalf("goal %s missing from goals[] rollup", goalID)
	}
	if goalRollup.MilestoneDone != 1 || goalRollup.MilestoneTotal != 2 {
		t.Errorf("goal milestones = %d/%d, want 1/2", goalRollup.MilestoneDone, goalRollup.MilestoneTotal)
	}
	if goalRollup.ProjectsTotal != 2 || goalRollup.ProjectsStalled != 1 {
		t.Errorf("goal projects total/stalled = %d/%d, want 2/1", goalRollup.ProjectsTotal, goalRollup.ProjectsStalled)
	}
}

// TestIntegration_ProjectProgress_AreaNeglect pins the area rollup: an area
// whose project's only human activity is 20 days old (>14) is neglected,
// while an area with a human event today is not. A non-human event inside
// the neglect window must NOT clear the flag.
func TestIntegration_ProjectProgress_AreaNeglect(t *testing.T) {
	s := setupServer(t)

	backendID := areaIDBySlug(t, "backend")
	studioID := areaIDBySlug(t, "studio")

	// backend: human active today → not neglected.
	bproj := seedProgressProject(t, "backend-proj", "Backend Proj", "weekly", nil, &backendID)
	seedActivityEvent(t, bproj, "human", time.Now())

	// studio: human active 20 days ago, plus a planner event today inside
	// the window — must stay neglected (agent doesn't reset the clock).
	sproj := seedProgressProject(t, "studio-proj", "Studio Proj", "weekly", nil, &studioID)
	seedActivityEvent(t, sproj, "human", time.Now().AddDate(0, 0, -20))
	seedActivityEvent(t, sproj, "planner", time.Now())

	_, out, err := callHandlerAs(t, "planner", s.projectProgress, ProjectProgressInput{})
	if err != nil {
		t.Fatalf("projectProgress: %v", err)
	}

	got := make(map[string]ProgressArea, len(out.Areas))
	for _, a := range out.Areas {
		got[a.Slug] = a
	}
	if a, ok := got["backend"]; !ok || a.AreaNeglected {
		t.Errorf("backend area_neglected = %v (present=%v), want false (human active today)", a.AreaNeglected, ok)
	}
	if a, ok := got["studio"]; !ok || !a.AreaNeglected {
		t.Errorf("studio area_neglected = %v (present=%v), want true (human silent 20 days; planner event must not count)", a.AreaNeglected, ok)
	}
}

// TestIntegration_ProjectProgress_CandidateFilter pins the candidate gate:
// proposed/archived projects and projects WITHOUT an expected_cadence are
// excluded from projects[]. Only in_progress|planned with a cadence appear.
func TestIntegration_ProjectProgress_CandidateFilter(t *testing.T) {
	s := setupServer(t)

	seedProgressProject(t, "candidate", "Candidate", "weekly", nil, nil)
	// No cadence → excluded.
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO projects (slug, title, status) VALUES ('no-cadence', 'No Cadence', 'in_progress')`,
	); err != nil {
		t.Fatalf("seed no-cadence project: %v", err)
	}
	// proposed → excluded even with a cadence.
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO projects (slug, title, status, expected_cadence, created_by)
		 VALUES ('proposed-proj', 'Proposed', 'proposed', 'weekly', 'planner')`,
	); err != nil {
		t.Fatalf("seed proposed project: %v", err)
	}

	_, out, err := callHandlerAs(t, "planner", s.projectProgress, ProjectProgressInput{})
	if err != nil {
		t.Fatalf("projectProgress: %v", err)
	}

	slugs := make(map[string]bool, len(out.Projects))
	for _, p := range out.Projects {
		slugs[p.Slug] = true
	}
	if !slugs["candidate"] {
		t.Errorf("candidate project missing from projects[]")
	}
	if slugs["no-cadence"] {
		t.Errorf("no-cadence project present in projects[], want excluded (cadence-less)")
	}
	if slugs["proposed-proj"] {
		t.Errorf("proposed project present in projects[], want excluded")
	}
}

// TestIntegration_ProjectProgress_CallerGate refuses the zero-privilege
// fallback and a fabricated caller — the owner's PARA must not be readable
// without a known identity, same gate as the readings tools.
func TestIntegration_ProjectProgress_CallerGate(t *testing.T) {
	s := setupServer(t)
	seedProgressProject(t, "gated", "Gated", "weekly", nil, nil)

	for _, caller := range []string{"unknown", "fabricated-agent"} {
		if _, _, err := callHandlerAs(t, caller, s.projectProgress, ProjectProgressInput{}); err == nil {
			t.Errorf("projectProgress as %q err = nil, want registered-caller refusal", caller)
		}
	}
}

// TestIntegration_ProposeContent_AsHermes drives propose_content as a
// registered agent and asserts the editorial contract on the persisted row:
// status=review (NOT published — an agent can never publish), is_public=false,
// created_by=the proposing agent, proposal_rationale persisted, and a slug
// derived from the title. It also asserts the row is NOT published.
func TestIntegration_ProposeContent_AsHermes(t *testing.T) {
	s := setupServer(t)

	_, out, err := callHandlerAs(t, "hermes", s.proposeContent, ProposeContentInput{
		Title:             "Value Semantics in Go",
		Type:              "article",
		Body:              "# Value Semantics\n\nA finished draft body.",
		Excerpt:           "Why Go copies.",
		ProposalRationale: "Finished the Obsidian Writing/articles draft; ready for review.",
	})
	if err != nil {
		t.Fatalf("proposeContent: %v", err)
	}
	if out.Content == nil || out.Content.ID == uuid.Nil {
		t.Fatal("proposeContent returned no content / zero ID")
	}
	if out.Content.Slug != "value-semantics-in-go" {
		t.Errorf("output slug = %q, want %q (derived from title)", out.Content.Slug, "value-semantics-in-go")
	}

	var (
		status            string
		isPublic          bool
		publishedAt       *time.Time
		createdBy         *string
		proposalRationale *string
	)
	if err := testPool.QueryRow(t.Context(),
		`SELECT status, is_public, published_at, created_by, proposal_rationale FROM contents WHERE id = $1`,
		out.Content.ID,
	).Scan(&status, &isPublic, &publishedAt, &createdBy, &proposalRationale); err != nil {
		t.Fatalf("reading proposed content: %v", err)
	}
	if status != "review" {
		t.Errorf("persisted status = %q, want %q (agent push lands in review, never published)", status, "review")
	}
	if isPublic {
		t.Error("persisted is_public = true, want false (agents cannot make content public)")
	}
	if publishedAt != nil {
		t.Errorf("persisted published_at = %v, want NULL (content is NOT published)", *publishedAt)
	}
	if createdBy == nil || *createdBy != "hermes" {
		t.Errorf("persisted created_by = %v, want %q", createdBy, "hermes")
	}
	if proposalRationale == nil || *proposalRationale != "Finished the Obsidian Writing/articles draft; ready for review." {
		t.Errorf("persisted proposal_rationale = %v, want the supplied rationale", proposalRationale)
	}
}

// TestIntegration_ProposeContent_CallerGate asserts the registered-caller gate:
// the zero-privilege "unknown" fallback and a fabricated name are refused
// before any write, so no contents row is created.
func TestIntegration_ProposeContent_CallerGate(t *testing.T) {
	s := setupServer(t)

	for _, caller := range []string{"unknown", "fabricated-agent"} {
		_, _, err := callHandlerAs(t, caller, s.proposeContent, ProposeContentInput{
			Title: "Should Never Persist",
			Type:  "article",
			Body:  "finished draft",
		})
		if err == nil {
			t.Errorf("proposeContent as %q err = nil, want registered-caller refusal", caller)
		}
	}

	var count int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM contents`,
	).Scan(&count); err != nil {
		t.Fatalf("counting contents: %v", err)
	}
	if count != 0 {
		t.Errorf("contents count = %d, want 0 (gate must precede any write)", count)
	}
}
