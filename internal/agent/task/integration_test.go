// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go bundles every testcontainers-backed test for the
// task package. Coverage is grouped into two concerns:
//
//   - Lifecycle & invariants — self-assignment rejection, Accept idempotency,
//     and the trg_tasks_completion_requires_outputs trigger path exercised
//     by Store.Complete.
//   - Concurrency — serialized position assignment under concurrent
//     AppendMessage goroutines hitting the same task, validating the
//     LockTaskForAppend + position-subquery pattern.
//
// Run with: go test -tags=integration ./internal/agent/task/...

package task

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/agent/artifact"
	"github.com/Koopa0/koopa/internal/testdb"
)

// testPool is the package-wide testcontainers pool bound in TestMain.
// Integration tests may read it directly; unit tests never touch it.
var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// --- Helpers ---

// seedAgents inserts fixture agents so task FKs and audit-trigger writes
// resolve. Returns (source, target) agent names.
//
// platform must be in the closed schema set (chk_agent_platform) —
// 'system' is the appropriate choice for fixtures that don't correspond
// to real registry agents. The 'system' row is also seeded because the
// activity_events audit trigger uses current_actor(), which falls back to
// the literal 'system' when koopa.actor is unset, and activity_events.actor
// is an FK into agents(name). testdb doesn't run BuiltinAgents() sync,
// so without this explicit seed the audit INSERT fails with 23503.
func seedAgents(t *testing.T) (source, target string) {
	t.Helper()
	ctx := t.Context()
	if _, err := testPool.Exec(ctx,
		`INSERT INTO agents (name, display_name, platform, description)
		 VALUES ('system', 'System', 'system', 'fallback actor for trigger writes without koopa.actor')
		 ON CONFLICT (name) DO NOTHING`); err != nil {
		t.Fatalf("seedAgents(system): %v", err)
	}
	source = "test-source"
	target = "test-target"
	for _, name := range []string{source, target} {
		_, err := testPool.Exec(ctx,
			`INSERT INTO agents (name, display_name, platform, description)
			 VALUES ($1, $1, 'system', 'integration test agent')
			 ON CONFLICT (name) DO NOTHING`, name)
		if err != nil {
			t.Fatalf("seedAgents(%q): %v", name, err)
		}
	}
	return source, target
}

// setup truncates the coordination tables and returns a fresh Store +
// Registry pair configured with the canonical test-source / test-target
// capabilities.
func setup(t *testing.T) (*Store, *agent.Registry) {
	t.Helper()
	testdb.Truncate(t, testPool, "artifacts", "task_messages", "tasks")
	artStore := artifact.NewStore(testPool)
	store := NewStore(testPool, artStore)
	registry := agent.NewRegistry([]agent.Agent{
		{
			Name:       "test-source",
			Platform:   "test",
			Capability: agent.Capability{SubmitTasks: true, PublishArtifacts: true},
			Status:     agent.StatusActive,
		},
		{
			Name:       "test-target",
			Platform:   "test",
			Capability: agent.Capability{ReceiveTasks: true, PublishArtifacts: true},
			Status:     agent.StatusActive,
		},
	})
	return store, registry
}

func textParts(text string) []*a2a.Part {
	return []*a2a.Part{a2a.NewTextPart(text)}
}

// appendInTx opens a tx with koopa.actor bound, runs one AppendMessage
// inside it, and commits. Kept as a standalone helper so the concurrent
// goroutine body stays below gocognit's complexity budget.
func appendInTx(ctx context.Context, store *Store, taskID uuid.UUID) error {
	tx, err := testPool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after commit; rollback errcheck satisfied via blank identifier

	if _, err := tx.Exec(ctx, "SELECT set_config('koopa.actor', 'test-target', true)"); err != nil {
		return fmt.Errorf("bind koopa.actor: %w", err)
	}
	if _, err := store.WithTx(tx).AppendMessage(ctx, taskID, RoleResponse, textParts("concurrent")); err != nil {
		return fmt.Errorf("append: %w", err)
	}
	return tx.Commit(ctx)
}

// --- Lifecycle & invariants ---

// TestSelfAssignmentRejected covers the chk_tasks_no_self_assignment
// constraint: source == target must be rejected at the DB layer even if
// the caller has SubmitTasks capability.
func TestSelfAssignmentRejected(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)

	auth, err := agent.Authorize(t.Context(), registry, "test-source", agent.ActionSubmitTask)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}

	_, err = store.Submit(t.Context(), auth, &SubmitInput{
		Source:       "test-source",
		Target:       "test-source", // same as source → CHECK violation
		Title:        "self-assigned task",
		RequestParts: textParts("request"),
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("Submit(self-assignment) error = %v, want %v", err, ErrInvalidInput)
	}
}

// TestAcceptNonSubmittedRejected covers Accept's idempotency contract:
// re-accepting an already-working task must yield ErrConflict, not a
// silent success.
func TestAcceptNonSubmittedRejected(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)

	submitAuth, err := agent.Authorize(t.Context(), registry, "test-source", agent.ActionSubmitTask)
	if err != nil {
		t.Fatalf("authorize submit: %v", err)
	}
	created, err := store.Submit(t.Context(), submitAuth, &SubmitInput{
		Source:       "test-source",
		Target:       "test-target",
		Title:        "test task",
		RequestParts: textParts("request"),
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	acceptAuth, err := agent.Authorize(t.Context(), registry, "test-target", agent.ActionAcceptTask)
	if err != nil {
		t.Fatalf("authorize accept: %v", err)
	}
	if _, err := store.Accept(t.Context(), acceptAuth, created.ID); err != nil {
		t.Fatalf("first Accept: %v", err)
	}

	if _, err := store.Accept(t.Context(), acceptAuth, created.ID); !errors.Is(err, ErrConflict) {
		t.Errorf("Accept(already-working) error = %v, want %v", err, ErrConflict)
	}
}

// TestCompletionRequiresOutputs exercises the happy path of
// Store.Complete: response message + artifact + state transition all land
// atomically, and the trg_tasks_completion_requires_outputs trigger does
// NOT fire because both child rows are visible when the UPDATE runs.
func TestCompletionRequiresOutputs(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)

	submitAuth, err := agent.Authorize(t.Context(), registry, "test-source", agent.ActionSubmitTask)
	if err != nil {
		t.Fatalf("authorize submit: %v", err)
	}
	created, err := store.Submit(t.Context(), submitAuth, &SubmitInput{
		Source:       "test-source",
		Target:       "test-target",
		Title:        "completable task",
		RequestParts: textParts("do the thing"),
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	acceptAuth, err := agent.Authorize(t.Context(), registry, "test-target", agent.ActionAcceptTask)
	if err != nil {
		t.Fatalf("authorize accept: %v", err)
	}
	if _, err := store.Accept(t.Context(), acceptAuth, created.ID); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	completeAuth, err := agent.Authorize(t.Context(), registry, "test-target", agent.ActionCompleteTask)
	if err != nil {
		t.Fatalf("authorize complete: %v", err)
	}
	completed, err := store.Complete(t.Context(), completeAuth, &CompleteInput{
		TaskID:        created.ID,
		ResponseParts: textParts("here is the result"),
		ArtifactName:  "result-report",
		ArtifactDesc:  "the deliverable",
		ArtifactParts: textParts("report content"),
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if completed.State != StateCompleted {
		t.Errorf("Complete state = %q, want %q", completed.State, StateCompleted)
	}
	if completed.CompletedAt == nil {
		t.Error("Complete completed_at is nil, want non-nil")
	}
}

// --- Concurrency ---

// TestAppendMessage_ConcurrentAssigns_SerializedPositions verifies that
// concurrent AppendMessage calls on the same task produce contiguous
// positions 0..N-1 without UNIQUE(task_id, position) violations. The
// LockTaskForAppend + MAX(position)-subquery pattern serializes
// concurrent appenders on the same task under READ COMMITTED; without
// the lock, two racers would both read MAX(position) before either
// INSERT commits, collide on position, and one would fail with 23505.
func TestAppendMessage_ConcurrentAssigns_SerializedPositions(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)

	ctx := t.Context()
	submitAuth, err := agent.Authorize(ctx, registry, "test-source", agent.ActionSubmitTask)
	if err != nil {
		t.Fatalf("authorize submit: %v", err)
	}
	created, err := store.Submit(ctx, submitAuth, &SubmitInput{
		Source:       "test-source",
		Target:       "test-target",
		Title:        "concurrent append target",
		RequestParts: textParts("initial"),
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	const appenders = 10
	var wg sync.WaitGroup
	errs := make([]error, appenders)
	for i := range appenders {
		wg.Go(func() { errs[i] = appendInTx(ctx, store, created.ID) })
	}
	wg.Wait()

	for i, e := range errs {
		if e != nil {
			t.Errorf("AppendMessage[%d] error = %v", i, e)
		}
	}

	// 1 message from Submit + N from concurrent appenders; positions must
	// be contiguous 0..N inclusive.
	messages, err := store.Messages(ctx, created.ID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	want := appenders + 1
	if len(messages) != want {
		t.Fatalf("message count = %d, want %d", len(messages), want)
	}
	for i := range messages {
		if messages[i].Position != int32(i) {
			t.Errorf("message[%d].Position = %d, want %d", i, messages[i].Position, i)
		}
	}
}

// countTaskArtifacts returns the number of artifacts attached to a task.
// Uses raw SQL to keep the assertion independent of the artifact.Store API
// shape — the trigger this test polices is a DB-layer invariant.
func countTaskArtifacts(t *testing.T, taskID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM artifacts WHERE task_id = $1`, taskID,
	).Scan(&n); err != nil {
		t.Fatalf("counting artifacts for task %s: %v", taskID, err)
	}
	return n
}

// countTaskResponseMessages returns the number of role='response' messages
// on a task. Same rationale as countTaskArtifacts.
func countTaskResponseMessages(t *testing.T, taskID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM task_messages WHERE task_id = $1 AND role = 'response'`, taskID,
	).Scan(&n); err != nil {
		t.Fatalf("counting response messages for task %s: %v", taskID, err)
	}
	return n
}

// TestCompletionWithoutArtifactRejected pins the trg_tasks_completion_requires_outputs
// invariant at the DB layer. Store.Complete is type-bound to require both a
// response message and an artifact, so the only way to reach the trigger
// without outputs is to bypass the Go API. This test does exactly that: it
// drives the bare state UPDATE via raw SQL on a working task that has a
// response message but no artifact, and asserts the trigger fires.
//
// Rationale: the type-level guarantee in CompleteInput is not the source of
// truth — the DB trigger is. If a future refactor introduces a separate
// transition path that forgets one of the outputs, this regression test
// catches it. The setup is intentionally minimal-but-valid (Submit + Accept
// + AppendMessage all succeed) so any failure points at the semantic
// invariant rather than malformed inputs.
func TestCompletionWithoutArtifactRejected(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)
	ctx := t.Context()

	submitAuth, err := agent.Authorize(ctx, registry, "test-source", agent.ActionSubmitTask)
	if err != nil {
		t.Fatalf("authorize submit: %v", err)
	}
	created, err := store.Submit(ctx, submitAuth, &SubmitInput{
		Source:       "test-source",
		Target:       "test-target",
		Title:        "completion-no-artifact",
		RequestParts: textParts("do the thing"),
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	acceptAuth, err := agent.Authorize(ctx, registry, "test-target", agent.ActionAcceptTask)
	if err != nil {
		t.Fatalf("authorize accept: %v", err)
	}
	if _, err := store.Accept(ctx, acceptAuth, created.ID); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	// Append a response message — alone it does NOT satisfy the trigger,
	// which requires both a response and an artifact. This isolates the
	// failure mode (artifact missing) from "no response either" so the
	// asserted trigger message points at the right invariant.
	if _, err := store.AppendMessage(ctx, created.ID, RoleResponse, textParts("done")); err != nil {
		t.Fatalf("AppendMessage response: %v", err)
	}
	if got := countTaskResponseMessages(t, created.ID); got != 1 {
		t.Fatalf("setup precondition: response count = %d, want 1", got)
	}
	if got := countTaskArtifacts(t, created.ID); got != 0 {
		t.Fatalf("setup precondition: artifact count = %d, want 0", got)
	}

	// Bypass Store.Complete (which is type-bound to require artifact parts)
	// and drive the state UPDATE through raw SQL. The BEFORE UPDATE OF
	// state trigger counts artifacts on this task_id and must raise P0001.
	_, err = testPool.Exec(ctx,
		`UPDATE tasks SET state = 'completed', completed_at = now() WHERE id = $1`,
		created.ID,
	)
	if err == nil {
		t.Fatalf("UPDATE tasks state=completed without artifact: err = nil, want trigger rejection")
	}
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
		t.Fatalf("UPDATE error = %T %v, want *pgconn.PgError from trg_tasks_completion_requires_outputs", err, err)
	}
	if pgErr.Code != pgerrcode.RaiseException {
		t.Errorf("pg error code = %q, want %q (P0001 from trigger RAISE EXCEPTION)", pgErr.Code, pgerrcode.RaiseException)
	}
	if !strings.Contains(pgErr.Message, "cannot transition to completed") {
		t.Errorf("pg error message = %q, want it to contain %q", pgErr.Message, "cannot transition to completed")
	}

	// Rejection must leave the task in working state, with completed_at unset.
	got, err := store.Task(ctx, created.ID)
	if err != nil {
		t.Fatalf("Task: %v", err)
	}
	if got.State != StateWorking {
		t.Errorf("state after rejected transition = %q, want %q", got.State, StateWorking)
	}
	if got.CompletedAt != nil {
		t.Errorf("completed_at after rejection = %v, want nil", got.CompletedAt)
	}
	if countTaskArtifacts(t, created.ID) != 0 {
		t.Errorf("artifact count after rejection != 0 — rejected UPDATE must not have created side effects")
	}
}

// TestRevisionRequestedLifecycle covers the completed → revision_requested
// → working → completed round-trip. The chk_tasks_state_timestamps CHECK
// pins tight (state, timestamp) invariants at every hop:
//
//   - completed:            completed_at NOT NULL, revision_requested_at NULL
//   - revision_requested:   completed_at NOT NULL, revision_requested_at NOT NULL
//   - working (post-Reaccept): completed_at NULL, revision_requested_at NULL
//   - completed (re-Complete): completed_at NOT NULL again
//
// Reaccept (ReacceptTask query) clears both completed_at and
// revision_requested_at so the working CHECK arm holds. Re-Complete
// satisfies trg_tasks_completion_requires_outputs by inserting a fresh
// response message + artifact; the trigger counts cumulative outputs on the
// task, so the existing first-cycle rows also count toward the ≥1 totals.
func TestRevisionRequestedLifecycle(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)
	ctx := t.Context()

	submitAuth, err := agent.Authorize(ctx, registry, "test-source", agent.ActionSubmitTask)
	if err != nil {
		t.Fatalf("authorize submit: %v", err)
	}
	created, err := store.Submit(ctx, submitAuth, &SubmitInput{
		Source:       "test-source",
		Target:       "test-target",
		Title:        "revision round-trip",
		RequestParts: textParts("first request"),
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	acceptAuth, err := agent.Authorize(ctx, registry, "test-target", agent.ActionAcceptTask)
	if err != nil {
		t.Fatalf("authorize accept: %v", err)
	}
	if _, err := store.Accept(ctx, acceptAuth, created.ID); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	completeAuth, err := agent.Authorize(ctx, registry, "test-target", agent.ActionCompleteTask)
	if err != nil {
		t.Fatalf("authorize complete: %v", err)
	}
	firstCompleted, err := store.Complete(ctx, completeAuth, &CompleteInput{
		TaskID:        created.ID,
		ResponseParts: textParts("first delivery"),
		ArtifactName:  "first-report",
		ArtifactDesc:  "initial deliverable",
		ArtifactParts: textParts("first artifact content"),
	})
	if err != nil {
		t.Fatalf("first Complete: %v", err)
	}
	if firstCompleted.State != StateCompleted {
		t.Fatalf("after first Complete: state = %q, want %q", firstCompleted.State, StateCompleted)
	}
	if firstCompleted.CompletedAt == nil {
		t.Fatal("after first Complete: completed_at is nil, want non-nil")
	}
	if firstCompleted.RevisionRequestedAt != nil {
		t.Errorf("after first Complete: revision_requested_at = %v, want nil", firstCompleted.RevisionRequestedAt)
	}
	if got := countTaskResponseMessages(t, created.ID); got != 1 {
		t.Errorf("after first Complete: response count = %d, want 1", got)
	}
	if got := countTaskArtifacts(t, created.ID); got != 1 {
		t.Errorf("after first Complete: artifact count = %d, want 1", got)
	}
	firstCompletedAt := *firstCompleted.CompletedAt

	// Source-side: request a revision. The chk_tasks_state_timestamps CHECK
	// arm for revision_requested requires completed_at to remain populated.
	revisionAuth, err := agent.Authorize(ctx, registry, "test-source", agent.ActionRequestRevision)
	if err != nil {
		t.Fatalf("authorize request_revision: %v", err)
	}
	revRequested, err := store.RequestRevision(ctx, revisionAuth, created.ID)
	if err != nil {
		t.Fatalf("RequestRevision: %v", err)
	}
	if revRequested.State != StateRevisionRequested {
		t.Errorf("after RequestRevision: state = %q, want %q", revRequested.State, StateRevisionRequested)
	}
	if revRequested.CompletedAt == nil || !revRequested.CompletedAt.Equal(firstCompletedAt) {
		t.Errorf("after RequestRevision: completed_at = %v, want preserved value %v", revRequested.CompletedAt, firstCompletedAt)
	}
	if revRequested.RevisionRequestedAt == nil {
		t.Error("after RequestRevision: revision_requested_at is nil, want non-nil")
	}

	// Assignee-side: pick the revision back up. ReacceptTask clears both
	// completed_at and revision_requested_at so the working CHECK holds.
	reacceptAuth, err := agent.Authorize(ctx, registry, "test-target", agent.ActionReacceptTask)
	if err != nil {
		t.Fatalf("authorize reaccept: %v", err)
	}
	reaccepted, err := store.Reaccept(ctx, reacceptAuth, created.ID)
	if err != nil {
		t.Fatalf("Reaccept: %v", err)
	}
	if reaccepted.State != StateWorking {
		t.Errorf("after Reaccept: state = %q, want %q", reaccepted.State, StateWorking)
	}
	if reaccepted.AcceptedAt == nil {
		t.Error("after Reaccept: accepted_at is nil, want preserved from original Accept")
	}
	if reaccepted.CompletedAt != nil {
		t.Errorf("after Reaccept: completed_at = %v, want nil (cleared)", reaccepted.CompletedAt)
	}
	if reaccepted.RevisionRequestedAt != nil {
		t.Errorf("after Reaccept: revision_requested_at = %v, want nil (cleared)", reaccepted.RevisionRequestedAt)
	}

	// Second Complete cycle. The trigger again gates the state UPDATE; the
	// new response + artifact rows ensure cumulative counts stay ≥1, so the
	// transition succeeds.
	secondCompleted, err := store.Complete(ctx, completeAuth, &CompleteInput{
		TaskID:        created.ID,
		ResponseParts: textParts("revised delivery"),
		ArtifactName:  "second-report",
		ArtifactDesc:  "post-revision deliverable",
		ArtifactParts: textParts("second artifact content"),
	})
	if err != nil {
		t.Fatalf("second Complete: %v", err)
	}
	if secondCompleted.State != StateCompleted {
		t.Errorf("after second Complete: state = %q, want %q", secondCompleted.State, StateCompleted)
	}
	if secondCompleted.CompletedAt == nil {
		t.Fatal("after second Complete: completed_at is nil, want non-nil")
	}
	if !secondCompleted.CompletedAt.After(firstCompletedAt) {
		t.Errorf("after second Complete: completed_at = %v, want strictly after first completion %v", secondCompleted.CompletedAt, firstCompletedAt)
	}
	if secondCompleted.RevisionRequestedAt != nil {
		t.Errorf("after second Complete: revision_requested_at = %v, want nil", secondCompleted.RevisionRequestedAt)
	}
	if got := countTaskResponseMessages(t, created.ID); got != 2 {
		t.Errorf("after second Complete: response count = %d, want 2", got)
	}
	if got := countTaskArtifacts(t, created.ID); got != 2 {
		t.Errorf("after second Complete: artifact count = %d, want 2", got)
	}
}
