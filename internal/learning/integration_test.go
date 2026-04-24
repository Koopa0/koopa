//go:build integration

// integration_test.go bundles every testcontainers-backed test for the
// learning package. Coverage is grouped into three concerns:
//
//  1. Symmetric relation trigger — trg_learning_target_relations_symmetry
//     auto-mirrors (A,B,same_pattern) to produce (B,A,same_pattern), and
//     must be idempotent + directed-type-safe.
//  2. FSRS drift signal — ErrUnknownOutcome bubbles up, MarkDrift stamps
//     the card, RetrievalQueue surfaces drift_suspect, and a subsequent
//     successful review clears the markers.
//  3. Session concurrency — the uq_learning_sessions_one_active partial
//     unique index enforces "one active session per domain" against
//     concurrent StartSession calls.
//
// Run with:
//
//	go test -tags=integration ./internal/learning/...
package learning_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/learning/fsrs"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool

	// BuiltinAgents must land in the agents table so FK targets are present
	// for every test that inserts via a handler path (or via seedTarget,
	// which references the 'leetcode' domain from migration 002).
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

// --- Helpers ---

// seedTarget inserts a learning_target in the leetcode domain (already
// seeded by migration 002) and returns its id. Uses an anonymous
// external_id derived from t.Name() so repeated invocations inside the
// same shared container do not collide on the (domain, external_id)
// partial unique index.
func seedTarget(t *testing.T, title string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_targets (domain, title, external_id)
		 VALUES ('leetcode', $1, $2)
		 RETURNING id`,
		title, t.Name()+"::"+title,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seeding learning_target %q: %v", title, err)
	}
	return id
}

// countRelations returns how many rows exist for the given (anchor,
// related, relation_type) triple. 0 or 1 under the unique index.
func countRelations(t *testing.T, anchor, related uuid.UUID, relType string) int {
	t.Helper()
	var n int
	err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM learning_target_relations
		 WHERE anchor_id = $1 AND related_id = $2 AND relation_type = $3`,
		anchor, related, relType,
	).Scan(&n)
	if err != nil {
		t.Fatalf("counting relations: %v", err)
	}
	return n
}

// truncateLearningTables clears every per-test learning row. Order is
// child-first so FK CASCADE chains stay consistent even when RESTART
// IDENTITY resets sequences.
func truncateLearningTables(t *testing.T) {
	t.Helper()
	_, err := testPool.Exec(t.Context(), `
		TRUNCATE
			review_logs,
			review_cards,
			learning_attempt_observations,
			learning_attempts,
			learning_sessions,
			learning_target_relations,
			learning_targets
		RESTART IDENTITY CASCADE
	`)
	if err != nil {
		t.Fatalf("truncateLearningTables: %v", err)
	}
}

// =========================================================================
// Section 1: Symmetric relation trigger
// =========================================================================
//
// made symmetric relation types
// (same_pattern, similar_structure) auto-mirror: a single INSERT of
// (A, B, same_pattern) produces two rows — (A, B) and (B, A) — via the
// AFTER INSERT trigger, with ON CONFLICT DO NOTHING preventing
// recursion.

// TestSymmetricRelation_InsertsReverseEdge — inserting one direction of
// a symmetric relation must produce both directions.
func TestSymmetricRelation_InsertsReverseEdge(t *testing.T) {
	a := seedTarget(t, "A-symmetric")
	b := seedTarget(t, "B-symmetric")

	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO learning_target_relations (anchor_id, related_id, relation_type)
		 VALUES ($1, $2, 'same_pattern')`,
		a, b,
	); err != nil {
		t.Fatalf("inserting forward edge: %v", err)
	}

	if got := countRelations(t, a, b, "same_pattern"); got != 1 {
		t.Errorf("forward (a→b) same_pattern count = %d, want 1", got)
	}
	if got := countRelations(t, b, a, "same_pattern"); got != 1 {
		t.Errorf("reverse (b→a) same_pattern count = %d, want 1 (trigger auto-insert)", got)
	}
}

// TestDirectedRelation_LeavesReverseEmpty — non-symmetric relation
// types must NOT auto-mirror. easier_variant is directed.
func TestDirectedRelation_LeavesReverseEmpty(t *testing.T) {
	a := seedTarget(t, "A-directed")
	b := seedTarget(t, "B-directed")

	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO learning_target_relations (anchor_id, related_id, relation_type)
		 VALUES ($1, $2, 'easier_variant')`,
		a, b,
	); err != nil {
		t.Fatalf("inserting directed edge: %v", err)
	}

	if got := countRelations(t, a, b, "easier_variant"); got != 1 {
		t.Errorf("forward easier_variant count = %d, want 1", got)
	}
	if got := countRelations(t, b, a, "easier_variant"); got != 0 {
		t.Errorf("reverse easier_variant count = %d, want 0 (directed type must not mirror)", got)
	}
}

// TestSymmetricRelation_ReverseInsertIdempotent — manually inserting
// the reverse edge of an already-mirrored pair must be a no-op (trigger
// would try to re-insert the forward edge; ON CONFLICT DO NOTHING
// keeps it terminating instead of recursing forever).
func TestSymmetricRelation_ReverseInsertIdempotent(t *testing.T) {
	a := seedTarget(t, "A-idempotent")
	b := seedTarget(t, "B-idempotent")

	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO learning_target_relations (anchor_id, related_id, relation_type)
		 VALUES ($1, $2, 'similar_structure')`,
		a, b,
	); err != nil {
		t.Fatalf("inserting first direction: %v", err)
	}

	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO learning_target_relations (anchor_id, related_id, relation_type)
		 VALUES ($1, $2, 'similar_structure')
		 ON CONFLICT DO NOTHING`,
		b, a,
	); err != nil {
		t.Fatalf("manual reverse insert should be a no-op: %v", err)
	}

	if got := countRelations(t, a, b, "similar_structure"); got != 1 {
		t.Errorf("forward similar_structure count = %d, want 1", got)
	}
	if got := countRelations(t, b, a, "similar_structure"); got != 1 {
		t.Errorf("reverse similar_structure count = %d, want 1 (no duplicate)", got)
	}
}

// =========================================================================
// Section 2: FSRS drift signal
// =========================================================================
//
// Compensating test for skipping the typed-outcome / exhaustive-linter
// path. The runtime safety net (ErrUnknownOutcome → MarkDrift →
// drift_suspect) is asserted here so a future refactor that reintroduces
// the silent-Again fallback fails loudly instead of quietly resetting
// every FSRS interval.

// TestDriftSignal_UnknownOutcome_SurfacedInRetrievalQueue exercises the
// full drift path: unknown-outcome review → ErrUnknownOutcome → MarkDrift
// → RetrievalQueue surfaces drift_suspect → known-outcome review clears
// it.
func TestDriftSignal_UnknownOutcome_SurfacedInRetrievalQueue(t *testing.T) {
	ctx := t.Context()
	truncateLearningTables(t)

	targetID := seedTarget(t, "two-sum-drift-test")

	fsrsStore := fsrs.NewStore(testPool)
	learnStore := learning.NewStore(testPool)

	now := time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)

	// Baseline: successful review creates a review_cards row. Without an
	// existing card, MarkDrift is a silent no-op — drift_suspect has
	// nowhere to land.
	baselineDue, err := fsrsStore.ReviewByOutcome(ctx, targetID, "solved_independent", now)
	if err != nil {
		t.Fatalf("baseline ReviewByOutcome: %v", err)
	}
	if baselineDue.Sub(now) < 24*time.Hour {
		t.Fatalf("baseline card due too soon: gap = %s, want >= 24h", baselineDue.Sub(now))
	}

	// Unknown outcome → sentinel must bubble up.
	driftTime := now.Add(time.Hour)
	_, err = fsrsStore.ReviewByOutcome(ctx, targetID, "bogus_outcome_value", driftTime)
	if !errors.Is(err, fsrs.ErrUnknownOutcome) {
		t.Fatalf("ReviewByOutcome(unknown) error = %v, want ErrUnknownOutcome", err)
	}

	// Stamp drift marker (this is what mcp.markFSRSDrift does in prod).
	rows, err := fsrsStore.MarkDrift(ctx, targetID, "unknown_outcome")
	if err != nil {
		t.Fatalf("MarkDrift: %v", err)
	}
	if rows != 1 {
		t.Fatalf("MarkDrift affected %d rows, want 1 (baseline card should exist)", rows)
	}

	// Retrieval queue must surface drift_suspect.
	dueBefore := driftTime.Add(365 * 24 * time.Hour) // cast wide: we just want the target returned
	items, err := learnStore.RetrievalQueue(ctx, nil, dueBefore, 50)
	if err != nil {
		t.Fatalf("RetrievalQueue: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("RetrievalQueue returned 0 items, want the drifted target")
	}

	var got *learning.RetrievalTarget
	for i := range items {
		if items[i].TargetID == targetID {
			got = &items[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("RetrievalQueue did not return target %s", targetID)
	}
	if !got.DriftSuspect {
		t.Errorf("drift_suspect = false, want true (last_sync_drift_at should be more recent than last attempt)")
	}
	if got.DriftReason == nil || *got.DriftReason != "unknown_outcome" {
		reason := "<nil>"
		if got.DriftReason != nil {
			reason = *got.DriftReason
		}
		t.Errorf("drift_reason = %q, want %q", reason, "unknown_outcome")
	}

	// A subsequent successful review must clear drift (forgiveness path —
	// drift is marked, never sticky).
	clearTime := driftTime.Add(time.Hour)
	if _, err := fsrsStore.ReviewByOutcome(ctx, targetID, "solved_independent", clearTime); err != nil {
		t.Fatalf("clearing ReviewByOutcome: %v", err)
	}

	items, err = learnStore.RetrievalQueue(ctx, nil, dueBefore, 50)
	if err != nil {
		t.Fatalf("RetrievalQueue (post-clear): %v", err)
	}
	for i := range items {
		if items[i].TargetID == targetID && items[i].DriftSuspect {
			t.Errorf("drift_suspect still true after successful review — drift markers not cleared by UpdateCardState")
		}
	}
}

// TestDriftSignal_MarkDrift_NoCardYet — MarkDrift on a target that has
// never had a review (no review_cards row) must be a silent no-op. The
// mcp layer logs this case so operators see drift-signal loss on
// brand-new targets; this test asserts the return shape the handler
// branches on.
func TestDriftSignal_MarkDrift_NoCardYet(t *testing.T) {
	ctx := t.Context()
	truncateLearningTables(t)

	targetID := seedTarget(t, "no-card-yet-drift-test")
	fsrsStore := fsrs.NewStore(testPool)

	rows, err := fsrsStore.MarkDrift(ctx, targetID, "unknown_outcome")
	if err != nil {
		t.Fatalf("MarkDrift on cardless target: %v", err)
	}
	if rows != 0 {
		t.Errorf("MarkDrift rows = %d, want 0 (no card yet — drift has nowhere to land)", rows)
	}
}

// TestDriftSignal_EmptyReason_Rejected — last_sync_drift_at and
// last_drift_reason are paired (schema CHECK chk_review_card_drift_pair).
// Empty reason is rejected at the Go layer before hitting the DB so
// callers get a clear error.
func TestDriftSignal_EmptyReason_Rejected(t *testing.T) {
	ctx := t.Context()
	truncateLearningTables(t)

	targetID := seedTarget(t, "empty-reason-drift-test")
	fsrsStore := fsrs.NewStore(testPool)

	_, err := fsrsStore.MarkDrift(ctx, targetID, "")
	if err == nil {
		t.Fatal("MarkDrift(empty reason) = nil, want error")
	}
}

// =========================================================================
// Section 3: Session concurrency
// =========================================================================

// TestStartSession_ConcurrentStart_OnlyOneWins — the
// uq_learning_sessions_one_active partial unique index makes concurrent
// StartSession calls on the same domain safe: exactly one wins with a
// live session, every other caller gets ErrActiveExists. Without the
// partial unique index, the in-process ActiveSession check is a TOCTOU
// window; the DB constraint is the real guarantee. A future migration
// that drops the partial unique index must fail this test.
func TestStartSession_ConcurrentStart_OnlyOneWins(t *testing.T) {
	truncateLearningTables(t)

	store := learning.NewStore(testPool)

	const callers = 10
	var (
		wg              sync.WaitGroup
		successCount    atomic.Int32
		activeExistsErr atomic.Int32
		otherErrs       atomic.Int32
	)

	for range callers {
		wg.Go(func() {
			_, _, err := store.StartSession(t.Context(), "leetcode", learning.ModePractice, nil)
			switch {
			case err == nil:
				successCount.Add(1)
			case errors.Is(err, learning.ErrActiveExists):
				activeExistsErr.Add(1)
			default:
				otherErrs.Add(1)
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	wg.Wait()

	if got := successCount.Load(); got != 1 {
		t.Errorf("successful StartSession count = %d, want 1", got)
	}
	if got := activeExistsErr.Load(); got != callers-1 {
		t.Errorf("ErrActiveExists count = %d, want %d", got, callers-1)
	}
	if got := otherErrs.Load(); got != 0 {
		t.Errorf("unexpected error count = %d, want 0", got)
	}
}
