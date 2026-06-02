// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// approve_test.go covers Store.Acknowledge — the source-side final
// acceptance of a completed task — and the request-revision interaction
// with acknowledgement. Every test sets up a real completed task and
// drives ack via a tx-bound store, exercising:
//
//   - happy path (with note, without note)
//   - repeated-approve idempotency (returns ErrAlreadyAcknowledged)
//   - wrong-state rejection (submitted / working / revision_requested / canceled)
//   - non-source rejection (capable caller != created_by)
//   - request_revision rejection once acked
//   - AwaitingApproval / Completed query separation
//   - audit event with change_kind='acknowledged'

package task

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/testdb"
)

// completedFixture submits, accepts, completes a task using the canonical
// test-source / test-target agents and returns the task ID. Each step
// runs in its own pool call; Complete is atomic in its own tx.
func completedFixture(t *testing.T, store *Store, registry *agent.Registry) uuid.UUID {
	t.Helper()
	ctx := t.Context()

	submitAuth, err := agent.Authorize(ctx, registry, "test-source", agent.ActionSubmitTask)
	if err != nil {
		t.Fatalf("authorize submit: %v", err)
	}
	created, err := store.Submit(ctx, submitAuth, &SubmitInput{
		Source:       "test-source",
		Target:       "test-target",
		Title:        "approve-fixture",
		RequestParts: textParts("request"),
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
	if _, err := store.Complete(ctx, completeAuth, &CompleteInput{
		TaskID:        created.ID,
		ResponseParts: textParts("delivered"),
		ArtifactName:  "result",
		ArtifactDesc:  "deliverable",
		ArtifactParts: textParts("content"),
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return created.ID
}

// approveInTx runs Acknowledge inside a tx with koopa.actor bound to
// caller, matching the production code path (api.ActorMiddleware /
// withActorTx). Returns the task after commit. The tx is rolled back if
// err is non-nil so caller-side assertions see a clean DB state.
func approveInTx(ctx context.Context, store *Store, caller, notes string, id uuid.UUID, auth agent.Authorized) (*Task, error) {
	tx, err := testPool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after commit

	if _, err := tx.Exec(ctx, "SELECT set_config('koopa.actor', $1, true)", caller); err != nil {
		return nil, err
	}
	t, err := store.WithTx(tx).Acknowledge(ctx, auth, id, notes)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return t, nil
}

// TestAcknowledgeHappyPath: completed + unacknowledged + source caller →
// acknowledged_at and acknowledged_by both set. No note appended when
// the caller passes an empty notes string.
func TestAcknowledgeHappyPath(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)
	ctx := t.Context()

	id := completedFixture(t, store, registry)

	auth, err := agent.Authorize(ctx, registry, "test-source", agent.ActionApproveTask)
	if err != nil {
		t.Fatalf("authorize approve: %v", err)
	}
	got, err := approveInTx(ctx, store, "test-source", "", id, auth)
	if err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	if got.AcknowledgedAt == nil {
		t.Error("Acknowledge: acknowledged_at = nil, want non-nil")
	}
	if got.AcknowledgedBy == nil || *got.AcknowledgedBy != "test-source" {
		t.Errorf("Acknowledge: acknowledged_by = %v, want %q", got.AcknowledgedBy, "test-source")
	}
	if got.State != StateCompleted {
		t.Errorf("Acknowledge: state = %q, want %q (state must NOT change)", got.State, StateCompleted)
	}
	// Empty notes → no new message appended (just the Submit request + Complete response).
	if n := countTaskResponseMessages(t, id); n != 1 {
		t.Errorf("response messages = %d, want 1 (no note appended for empty notes)", n)
	}
}

// TestAcknowledgeWithNote: a non-empty notes string appends exactly one
// RoleResponse message in the same tx as the ack update.
func TestAcknowledgeWithNote(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)
	ctx := t.Context()

	id := completedFixture(t, store, registry)
	auth, err := agent.Authorize(ctx, registry, "test-source", agent.ActionApproveTask)
	if err != nil {
		t.Fatalf("authorize approve: %v", err)
	}

	if _, err := approveInTx(ctx, store, "test-source", "looks great", id, auth); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	if n := countTaskResponseMessages(t, id); n != 2 {
		t.Errorf("response messages = %d, want 2 (Complete response + approval note)", n)
	}
}

// TestAcknowledgeRepeatedConflict: a second Acknowledge on an
// already-acked task returns ErrAlreadyAcknowledged and does not append
// a second message even if notes are supplied.
func TestAcknowledgeRepeatedConflict(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)
	ctx := t.Context()

	id := completedFixture(t, store, registry)
	auth, err := agent.Authorize(ctx, registry, "test-source", agent.ActionApproveTask)
	if err != nil {
		t.Fatalf("authorize approve: %v", err)
	}
	if _, err := approveInTx(ctx, store, "test-source", "first", id, auth); err != nil {
		t.Fatalf("first Acknowledge: %v", err)
	}
	msgCountAfterFirst := countTaskResponseMessages(t, id)

	_, err = approveInTx(ctx, store, "test-source", "second", id, auth)
	if !errors.Is(err, ErrAlreadyAcknowledged) {
		t.Errorf("second Acknowledge: err = %v, want %v", err, ErrAlreadyAcknowledged)
	}
	if n := countTaskResponseMessages(t, id); n != msgCountAfterFirst {
		t.Errorf("response messages after second Acknowledge = %d, want %d (no second note)", n, msgCountAfterFirst)
	}
}

// TestAcknowledgeWrongState: acknowledging a task in submitted /
// working / revision_requested / canceled state must reject with
// ErrConflict (not ErrAlreadyAcknowledged — the ack column is NULL).
func TestAcknowledgeWrongState(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, store *Store, registry *agent.Registry) uuid.UUID
	}{
		{
			name: "submitted",
			setup: func(t *testing.T, store *Store, registry *agent.Registry) uuid.UUID {
				t.Helper()
				submitAuth, err := agent.Authorize(t.Context(), registry, "test-source", agent.ActionSubmitTask)
				if err != nil {
					t.Fatalf("authorize submit: %v", err)
				}
				task, err := store.Submit(t.Context(), submitAuth, &SubmitInput{
					Source: "test-source", Target: "test-target",
					Title: "submitted-task", RequestParts: textParts("r"),
				})
				if err != nil {
					t.Fatalf("Submit: %v", err)
				}
				return task.ID
			},
		},
		{
			name: "working",
			setup: func(t *testing.T, store *Store, registry *agent.Registry) uuid.UUID {
				t.Helper()
				submitAuth, _ := agent.Authorize(t.Context(), registry, "test-source", agent.ActionSubmitTask)
				task, _ := store.Submit(t.Context(), submitAuth, &SubmitInput{
					Source: "test-source", Target: "test-target",
					Title: "working-task", RequestParts: textParts("r"),
				})
				acceptAuth, _ := agent.Authorize(t.Context(), registry, "test-target", agent.ActionAcceptTask)
				if _, err := store.Accept(t.Context(), acceptAuth, task.ID); err != nil {
					t.Fatalf("Accept: %v", err)
				}
				return task.ID
			},
		},
		{
			name: "revision_requested",
			setup: func(t *testing.T, store *Store, registry *agent.Registry) uuid.UUID {
				t.Helper()
				id := completedFixture(t, store, registry)
				revAuth, _ := agent.Authorize(t.Context(), registry, "test-source", agent.ActionRequestRevision)
				if _, err := store.RequestRevision(t.Context(), revAuth, id); err != nil {
					t.Fatalf("RequestRevision: %v", err)
				}
				return id
			},
		},
		{
			name: "canceled",
			setup: func(t *testing.T, store *Store, registry *agent.Registry) uuid.UUID {
				t.Helper()
				submitAuth, _ := agent.Authorize(t.Context(), registry, "test-source", agent.ActionSubmitTask)
				task, _ := store.Submit(t.Context(), submitAuth, &SubmitInput{
					Source: "test-source", Target: "test-target",
					Title: "canceled-task", RequestParts: textParts("r"),
				})
				cancelAuth, _ := agent.Authorize(t.Context(), registry, "test-source", agent.ActionCancelTask)
				if _, err := store.Cancel(t.Context(), cancelAuth, task.ID); err != nil {
					t.Fatalf("Cancel: %v", err)
				}
				return task.ID
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, registry := setup(t)
			seedAgents(t)
			id := tc.setup(t, store, registry)
			auth, err := agent.Authorize(t.Context(), registry, "test-source", agent.ActionApproveTask)
			if err != nil {
				t.Fatalf("authorize approve: %v", err)
			}
			_, err = approveInTx(t.Context(), store, "test-source", "", id, auth)
			if !errors.Is(err, ErrConflict) {
				t.Errorf("Acknowledge(state=%s): err = %v, want %v", tc.name, err, ErrConflict)
			}
		})
	}
}

// TestAcknowledgeNonSourceRejected: an agent that holds SubmitTasks
// capability but did not create the task must NOT be able to
// acknowledge it. Store-layer enforcement, not handler preflight.
func TestAcknowledgeNonSourceRejected(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)
	ctx := t.Context()

	// Add a second capable agent to the registry so Authorize() succeeds
	// for the capability check; the store-layer source-bind is what we
	// want to fail.
	registry = agent.NewRegistry([]agent.Agent{
		{Name: "test-source", Platform: "test", Capability: agent.Capability{SubmitTasks: true, PublishArtifacts: true}, Status: agent.StatusActive},
		{Name: "test-target", Platform: "test", Capability: agent.Capability{ReceiveTasks: true, PublishArtifacts: true}, Status: agent.StatusActive},
		{Name: "test-stranger", Platform: "test", Capability: agent.Capability{SubmitTasks: true}, Status: agent.StatusActive},
	})
	if _, err := testPool.Exec(ctx,
		`INSERT INTO agents (name, display_name, platform, description)
		 VALUES ('test-stranger', 'test-stranger', 'system', 'non-source approver')
		 ON CONFLICT (name) DO NOTHING`); err != nil {
		t.Fatalf("seed stranger: %v", err)
	}

	id := completedFixture(t, store, registry)

	auth, err := agent.Authorize(ctx, registry, "test-stranger", agent.ActionApproveTask)
	if err != nil {
		t.Fatalf("authorize approve: %v", err)
	}
	_, err = approveInTx(ctx, store, "test-stranger", "", id, auth)
	if !errors.Is(err, agent.ErrForbidden) {
		t.Errorf("Acknowledge(non-source): err = %v, want %v", err, agent.ErrForbidden)
	}
	// No ack should have landed.
	got, err := store.Task(ctx, id)
	if err != nil {
		t.Fatalf("Task: %v", err)
	}
	if got.AcknowledgedAt != nil {
		t.Errorf("acknowledged_at after non-source attempt = %v, want nil", got.AcknowledgedAt)
	}
}

// TestRequestRevisionRejectsAcknowledged: once a completed task has been
// acked, RequestRevision must reject with ErrConflict — the
// acknowledged_at IS NULL guard on the underlying query bakes the
// invariant in below the handler layer.
func TestRequestRevisionRejectsAcknowledged(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)
	ctx := t.Context()

	id := completedFixture(t, store, registry)
	approveAuth, err := agent.Authorize(ctx, registry, "test-source", agent.ActionApproveTask)
	if err != nil {
		t.Fatalf("authorize approve: %v", err)
	}
	if _, err := approveInTx(ctx, store, "test-source", "", id, approveAuth); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}

	revAuth, err := agent.Authorize(ctx, registry, "test-source", agent.ActionRequestRevision)
	if err != nil {
		t.Fatalf("authorize request_revision: %v", err)
	}
	_, err = store.RequestRevision(ctx, revAuth, id)
	if !errors.Is(err, ErrConflict) {
		t.Errorf("RequestRevision(acked): err = %v, want %v", err, ErrConflict)
	}
	got, err := store.Task(ctx, id)
	if err != nil {
		t.Fatalf("Task: %v", err)
	}
	if got.State != StateCompleted {
		t.Errorf("state after rejected RequestRevision = %q, want %q", got.State, StateCompleted)
	}
	if got.AcknowledgedAt == nil {
		t.Error("acknowledged_at was cleared by rejected RequestRevision — invariant violation")
	}
}

// TestAwaitingApprovalScope: AwaitingApprovalPaged returns only completed
// + unacknowledged tasks. CompletedPaged keeps including acked tasks
// (history view). The two queries together cover the completed surface
// without double-counting or omission.
func TestAwaitingApprovalScope(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)
	ctx := t.Context()

	unacked := completedFixture(t, store, registry)
	acked := completedFixture(t, store, registry)

	approveAuth, err := agent.Authorize(ctx, registry, "test-source", agent.ActionApproveTask)
	if err != nil {
		t.Fatalf("authorize approve: %v", err)
	}
	if _, err := approveInTx(ctx, store, "test-source", "", acked, approveAuth); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}

	awaiting, total, err := store.AwaitingApprovalPaged(ctx, 1, 50)
	if err != nil {
		t.Fatalf("AwaitingApprovalPaged: %v", err)
	}
	if total != 1 {
		t.Errorf("AwaitingApproval total = %d, want 1", total)
	}
	if len(awaiting) != 1 || awaiting[0].ID != unacked {
		t.Errorf("AwaitingApproval rows = %v, want exactly the unacked task %s", awaiting, unacked)
	}

	completed, total, err := store.CompletedPaged(ctx, 1, 50)
	if err != nil {
		t.Fatalf("CompletedPaged: %v", err)
	}
	if total != 2 {
		t.Errorf("Completed total = %d, want 2 (history includes acked)", total)
	}
	ids := map[uuid.UUID]bool{}
	for _, r := range completed {
		ids[r.ID] = true
	}
	if !ids[unacked] || !ids[acked] {
		t.Errorf("Completed rows = %v, want both unacked %s and acked %s", completed, unacked, acked)
	}
}

// TestAcknowledgeAuditEvent: the audit trigger writes exactly one
// activity_events row with change_kind='acknowledged' and actor =
// koopa.actor bound by the tx.
func TestAcknowledgeAuditEvent(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)
	testdb.Truncate(t, testPool, "activity_events", "artifacts", "task_messages", "tasks")
	ctx := t.Context()

	id := completedFixture(t, store, registry)
	auth, err := agent.Authorize(ctx, registry, "test-source", agent.ActionApproveTask)
	if err != nil {
		t.Fatalf("authorize approve: %v", err)
	}
	if _, err := approveInTx(ctx, store, "test-source", "", id, auth); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}

	var n int
	var actor string
	if err := testPool.QueryRow(ctx,
		`SELECT COUNT(*), MAX(actor) FROM activity_events
		 WHERE entity_type='task' AND entity_id=$1 AND change_kind='acknowledged'`,
		id,
	).Scan(&n, &actor); err != nil {
		t.Fatalf("query activity_events: %v", err)
	}
	if n != 1 {
		t.Errorf("acknowledged events = %d, want 1", n)
	}
	if actor != "test-source" {
		t.Errorf("acknowledged event actor = %q, want %q", actor, "test-source")
	}
}

// TestTodayAwaitingSource_ExcludesAcknowledged proves the today adapter
// returns only completed + unacknowledged tasks, with the exclusion
// applied server-side by AwaitingApprovalPaged (not by any caller-side
// filter). It also locks the task.Task → today.JudgmentTask projection:
// JudgmentTask.Source maps the task source (created_by) and
// JudgmentTask.Assignee maps the task target (assignee column).
func TestTodayAwaitingSource_ExcludesAcknowledged(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)
	ctx := t.Context()

	unacked := completedFixture(t, store, registry)
	acked := completedFixture(t, store, registry)

	approveAuth, err := agent.Authorize(ctx, registry, "test-source", agent.ActionApproveTask)
	if err != nil {
		t.Fatalf("authorize approve: %v", err)
	}
	if _, err := approveInTx(ctx, store, "test-source", "", acked, approveAuth); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}

	got, err := NewTodayAwaitingSource(store).AwaitingApproval(ctx, 50)
	if err != nil {
		t.Fatalf("AwaitingApproval: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("AwaitingApproval len = %d, want 1 (acked task excluded server-side)", len(got))
	}
	if got[0].ID != unacked {
		t.Errorf("AwaitingApproval[0].ID = %s, want unacked task %s", got[0].ID, unacked)
	}
	if got[0].Source != "test-source" {
		t.Errorf("JudgmentTask.Source = %q, want %q (task source / created_by)", got[0].Source, "test-source")
	}
	if got[0].Assignee != "test-target" {
		t.Errorf("JudgmentTask.Assignee = %q, want %q (task target / assignee)", got[0].Assignee, "test-target")
	}
	if got[0].CompletedAt == nil {
		t.Error("JudgmentTask.CompletedAt = nil, want non-nil for a completed task")
	}
}

// TestAcknowledgeMissingTask: a non-existent task ID returns ErrNotFound,
// not ErrConflict. The locked-read produces pgx.ErrNoRows which the
// store translates explicitly.
func TestAcknowledgeMissingTask(t *testing.T) {
	store, registry := setup(t)
	seedAgents(t)
	ctx := t.Context()

	auth, err := agent.Authorize(ctx, registry, "test-source", agent.ActionApproveTask)
	if err != nil {
		t.Fatalf("authorize approve: %v", err)
	}
	missing := uuid.New()
	_, err = approveInTx(ctx, store, "test-source", "", missing, auth)
	if !errors.Is(err, ErrNotFound) && !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("Acknowledge(missing): err = %v, want %v", err, ErrNotFound)
	}
}
