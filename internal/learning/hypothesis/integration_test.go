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
	if _, err := agent.SyncToTable(context.Background(), registry, agent.NewStore(pool), slog.Default()); err != nil {
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
