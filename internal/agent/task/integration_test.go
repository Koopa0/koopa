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
	"sync"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/uuid"
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
func seedAgents(t *testing.T) (string, string) {
	t.Helper()
	ctx := t.Context()
	if _, err := testPool.Exec(ctx,
		`INSERT INTO agents (name, display_name, platform, description)
		 VALUES ('system', 'System', 'system', 'fallback actor for trigger writes without koopa.actor')
		 ON CONFLICT (name) DO NOTHING`); err != nil {
		t.Fatalf("seedAgents(system): %v", err)
	}
	source := "test-source"
	target := "test-target"
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
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

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
