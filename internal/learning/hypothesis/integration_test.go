// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// Integration coverage for the hypothesis verify runtime fix (V2). A
// hypothesis moves from state='unverified' into 'verified' only when
// resolved_at is set AND at least one evidence source is supplied —
// chk_hypothesis_resolved_at + chk_hypothesis_resolution enforce both.
// Before V2 the verify handler called UpdateHypothesisState which only
// changed state, leaving resolved_at NULL and guaranteeing a 23514
// CHECK violation. This test POSTs through the real handler chain and
// reads the row back, asserting state='verified', resolved_at is non-
// NULL, and resolution_summary matches.
//
// Run with:
//
//	go test -tags=integration ./internal/learning/hypothesis/...
package hypothesis_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/learning/hypothesis"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool

	// hypotheses.created_by FKs onto agents; without the registry seeded,
	// seedHypothesis below fails 23503 before it can set up the test.
	registry := agent.NewBuiltinRegistry()
	if _, err := agent.SyncToTable(context.Background(), registry, agent.NewStore(pool), nil, slog.Default()); err != nil {
		slog.Default().Error("agent.SyncToTable", "error", err)
		cleanup()
		os.Exit(1)
	}

	code := m.Run()
	cleanup()
	os.Exit(code)
}

// seedHypothesis inserts an unverified hypothesis via SQL and returns
// its id. Going direct bypasses the handler's own validation so the
// test focuses on the verify path, not on the create path.
func seedHypothesis(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(t.Context(),
		`INSERT INTO learning_hypotheses (created_by, content, claim, invalidation_condition, observed_date)
		 VALUES ('human', $1, $2, $3, CURRENT_DATE)
		 RETURNING id`,
		"test content",
		"test claim",
		"would be invalid if X",
	).Scan(&id)
	if err != nil {
		t.Fatalf("seeding hypothesis: %v", err)
	}
	return id
}

// TestIntegration_Hypothesis_Create_HappyPath drives
// POST /api/admin/learning/hypotheses through the actor middleware and asserts
// the hypothesis persists in state=unverified with the claim + invalidation
// condition and actor=human on its audit row.
func TestIntegration_Hypothesis_Create_HappyPath(t *testing.T) {
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE learning_hypotheses, activity_events CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	store := hypothesis.NewStore(testPool)
	h := hypothesis.NewHandler(store, slog.Default())

	body, err := json.Marshal(map[string]any{
		"content":                "I keep failing graph DFS termination.",
		"claim":                  "DFS termination is my weakest LeetCode skill",
		"invalidation_condition": "three clean graph solves in a row",
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/learning/hypotheses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := serveAdmin(t, h.Create, req)

	resp := rec.Result()
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", resp.StatusCode, string(respBody))
	}

	var env struct {
		Data struct {
			ID uuid.UUID `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &env); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, respBody)
	}
	if env.Data.ID == uuid.Nil {
		t.Fatalf("response missing id: %s", respBody)
	}

	// The hypothesis audit trigger fires only AFTER UPDATE OF state, never on
	// INSERT, so create writes no activity_events row. Provenance for the
	// create path is the created_by column, stamped from the tx-bound actor.
	var state, claim, createdBy string
	if err := testPool.QueryRow(t.Context(),
		`SELECT state::text, claim, created_by FROM learning_hypotheses WHERE id = $1`, env.Data.ID,
	).Scan(&state, &claim, &createdBy); err != nil {
		t.Fatalf("reading created hypothesis: %v", err)
	}
	if state != "unverified" {
		t.Errorf("state = %q, want %q (create always lands unverified)", state, "unverified")
	}
	if claim != "DFS termination is my weakest LeetCode skill" {
		t.Errorf("claim = %q, want the submitted claim", claim)
	}
	if createdBy != "human" {
		t.Errorf("created_by = %q, want %q (tx-bound actor did not reach the stamp)", createdBy, "human")
	}
}

// TestIntegration_Hypothesis_Create_MissingClaim asserts the handler rejects a
// create missing the required claim with 400 before any write.
func TestIntegration_Hypothesis_Create_MissingClaim(t *testing.T) {
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE learning_hypotheses, activity_events CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	store := hypothesis.NewStore(testPool)
	h := hypothesis.NewHandler(store, slog.Default())

	body, err := json.Marshal(map[string]any{
		"invalidation_condition": "something",
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/learning/hypotheses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := serveAdmin(t, h.Create, req)

	resp := rec.Result()
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for missing claim (body=%s)", resp.StatusCode, string(respBody))
	}

	var count int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM learning_hypotheses`,
	).Scan(&count); err != nil {
		t.Fatalf("counting hypotheses: %v", err)
	}
	if count != 0 {
		t.Errorf("hypothesis count = %d, want 0 (validation must precede any write)", count)
	}
}

// serveAdmin runs a request through api.ActorMiddleware (actor="human") into
// the handler, mirroring the production adminMid chain that binds the tx the
// create path reads for the created_by stamp and audit actor.
func serveAdmin(t *testing.T, h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	mid := api.ActorMiddleware(testPool, "human", slog.Default())
	wrapped := mid(h)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	return rec
}

// TestHypothesisVerify_DoesNotViolateCheckConstraint is the V2 regression
// guard. Before commit 21 POSTing /verify with just a summary would 500
// because UpdateHypothesisState didn't set resolved_at, violating
// chk_hypothesis_resolved_at. After V2, UpdateResolution writes state,
// resolved_at, and the evidence fields atomically inside one query.
func TestHypothesisVerify_DoesNotViolateCheckConstraint(t *testing.T) {
	id := seedHypothesis(t, testPool)

	store := hypothesis.NewStore(testPool)
	h := hypothesis.NewHandler(store, slog.Default())

	body, err := json.Marshal(map[string]string{
		"resolution_summary": "test evidence",
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hypotheses/"+id.String()+"/verify", bytes.NewReader(body))
	req.SetPathValue("id", id.String())
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.Verify(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, string(respBody))
	}

	// Read the row back and verify every column the V2 fix touches.
	var (
		state             string
		resolvedAt        *time.Time
		resolutionSummary *string
	)
	err = testPool.QueryRow(t.Context(),
		`SELECT state::text, resolved_at, resolution_summary FROM learning_hypotheses WHERE id = $1`,
		id,
	).Scan(&state, &resolvedAt, &resolutionSummary)
	if err != nil {
		t.Fatalf("reading hypothesis row: %v", err)
	}

	if state != "verified" {
		t.Errorf("state = %q, want %q", state, "verified")
	}
	if resolvedAt == nil {
		t.Error("resolved_at is NULL, want non-NULL (chk_hypothesis_resolved_at invariant)")
	}
	if resolutionSummary == nil || *resolutionSummary != "test evidence" {
		got := "<nil>"
		if resolutionSummary != nil {
			got = *resolutionSummary
		}
		t.Errorf("resolution_summary = %q, want %q", got, "test evidence")
	}
}

// TestAppendEvidence_ConcurrentAppendsPreserveAllEntries is the C2
// regression guard. Before commit 26, AddEvidence read the row, mutated
// metadata.supporting_evidence in memory, and wrote it back via
// UpdateMetadata. Two concurrent appends under Read Committed could
// both read the same pre-state and both write a single-element array,
// silently dropping one entry. AppendEvidence now runs one UPDATE per
// request with jsonb_set + jsonb || jsonb, which PostgreSQL serializes
// at the row level — each request's append operates on the latest
// metadata value.
//
// The test fires N concurrent AppendEvidence calls and then asserts
// the final supporting_evidence array has exactly N elements. If the
// TOCTOU comes back, the length will be less than N.
func TestAppendEvidence_ConcurrentAppendsPreserveAllEntries(t *testing.T) {
	const n = 20

	id := seedHypothesis(t, testPool)
	store := hypothesis.NewStore(testPool)

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Go(func() {
			entry, err := json.Marshal(map[string]any{
				"type":        "supporting",
				"description": "concurrent entry",
				"seq":         i,
			})
			if err != nil {
				errs <- err
				return
			}
			if _, err := store.AppendEvidence(t.Context(), id, "supporting", entry); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("AppendEvidence concurrent call: %v", err)
	}

	// Read back and count supporting_evidence entries. A pre-fix run
	// with the read-modify-write path typically lost 3-10 entries out
	// of 20 on this box.
	var count int
	if err := testPool.QueryRow(t.Context(),
		`SELECT jsonb_array_length(metadata -> 'supporting_evidence') FROM learning_hypotheses WHERE id = $1`,
		id,
	).Scan(&count); err != nil {
		t.Fatalf("reading supporting_evidence length: %v", err)
	}

	if count != n {
		t.Errorf("AppendEvidence(x%d) persisted %d entries, want %d (lost %d to TOCTOU)",
			n, count, n, n-count)
	}
}

// ---------------------------------------------------------------------------
// v3.1 inert drafts — endorse / draft-only delete / triage list filter
// ---------------------------------------------------------------------------

// seedDraftHypothesis inserts a state=draft row directly via SQL — the
// fixture equivalent of what the MCP draft_hypothesis tool writes.
func seedDraftHypothesis(t *testing.T, pool *pgxpool.Pool, claim string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(t.Context(),
		`INSERT INTO learning_hypotheses (created_by, content, state, claim, invalidation_condition, observed_date)
		 VALUES ('planner', '', 'draft', $1, 'would be invalid if X', CURRENT_DATE)
		 RETURNING id`,
		claim,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seeding draft hypothesis: %v", err)
	}
	return id
}

// TestIntegration_Hypothesis_Endorse drives the draft → unverified owner
// stamp through the real handler chain: happy path 200 + row lands in
// unverified, re-endorsing the now-unverified row 409 NOT_DRAFT, and a
// missing id 404.
func TestIntegration_Hypothesis_Endorse(t *testing.T) {
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE learning_hypotheses, activity_events CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	store := hypothesis.NewStore(testPool)
	h := hypothesis.NewHandler(store, slog.Default())
	id := seedDraftHypothesis(t, testPool, "graph problems keep failing on DFS termination")

	endorse := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost,
			"/api/admin/learning/hypotheses/"+target+"/endorse", http.NoBody)
		req.SetPathValue("id", target)
		return serveAdmin(t, h.Endorse, req)
	}

	// Happy path: draft → unverified.
	rec := endorse(id.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("endorse(draft) status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var state string
	if err := testPool.QueryRow(t.Context(),
		`SELECT state::text FROM learning_hypotheses WHERE id = $1`, id,
	).Scan(&state); err != nil {
		t.Fatalf("reading endorsed row: %v", err)
	}
	if state != "unverified" {
		t.Errorf("state after endorse = %q, want %q", state, "unverified")
	}

	// Non-draft: the row is now unverified — endorsing again must 409.
	rec = endorse(id.String())
	if rec.Code != http.StatusConflict {
		t.Errorf("endorse(unverified) status = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
	}

	// Missing row → 404.
	rec = endorse(uuid.NewString())
	if rec.Code != http.StatusNotFound {
		t.Errorf("endorse(missing) status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestIntegration_Hypothesis_DeleteDraftOnly drives the draft-only DELETE:
// removing a draft returns 204 and the row is gone; an unverified row is a
// permanent record — DELETE returns 409 and the row survives.
func TestIntegration_Hypothesis_DeleteDraftOnly(t *testing.T) {
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE learning_hypotheses, activity_events CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	store := hypothesis.NewStore(testPool)
	h := hypothesis.NewHandler(store, slog.Default())

	del := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete,
			"/api/admin/learning/hypotheses/"+target, http.NoBody)
		req.SetPathValue("id", target)
		return serveAdmin(t, h.Delete, req)
	}

	// Draft → 204 and gone.
	draftID := seedDraftHypothesis(t, testPool, "deletable draft")
	rec := del(draftID.String())
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete(draft) status = %d, want 204 (body=%s)", rec.Code, rec.Body.String())
	}
	var count int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM learning_hypotheses WHERE id = $1`, draftID,
	).Scan(&count); err != nil {
		t.Fatalf("counting deleted draft: %v", err)
	}
	if count != 0 {
		t.Errorf("draft row count after delete = %d, want 0", count)
	}

	// Unverified → 409 and the permanent record survives.
	permanentID := seedHypothesis(t, testPool)
	rec = del(permanentID.String())
	if rec.Code != http.StatusConflict {
		t.Errorf("delete(unverified) status = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
	}
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM learning_hypotheses WHERE id = $1`, permanentID,
	).Scan(&count); err != nil {
		t.Fatalf("counting unverified row: %v", err)
	}
	if count != 1 {
		t.Errorf("unverified row count after refused delete = %d, want 1 (permanent record must survive)", count)
	}
}

// TestIntegration_Hypothesis_ListStateFilter pins the admin triage surface:
// the unfiltered list shows drafts alongside everything else, and
// ?state=draft narrows to drafts only. This is the ONE surface where
// drafts are deliberately visible.
func TestIntegration_Hypothesis_ListStateFilter(t *testing.T) {
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE learning_hypotheses, activity_events CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	store := hypothesis.NewStore(testPool)
	h := hypothesis.NewHandler(store, slog.Default())
	seedDraftHypothesis(t, testPool, "draft claim for triage")
	seedHypothesis(t, testPool) // unverified

	list := func(query string) []hypothesis.Record {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/admin/learning/hypotheses"+query, http.NoBody)
		rec := httptest.NewRecorder()
		h.List(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("list(%q) status = %d, want 200 (body=%s)", query, rec.Code, rec.Body.String())
		}
		var env struct {
			Data []hypothesis.Record `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode list response: %v (body=%s)", err, rec.Body.String())
		}
		return env.Data
	}

	if got := list(""); len(got) != 2 {
		t.Errorf("unfiltered list len = %d, want 2 (draft + unverified)", len(got))
	}
	drafts := list("?state=draft")
	if len(drafts) != 1 || drafts[0].State != hypothesis.StateDraft {
		t.Errorf("list(state=draft) = %+v, want exactly one draft row", drafts)
	}
}
