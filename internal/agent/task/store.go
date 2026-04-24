package task

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/agent/artifact"
	"github.com/Koopa0/koopa/internal/db"
)

// Store handles persistence for tasks and their attached message log,
// and owns the atomic Complete path that also writes to artifacts.
//
// Mutation methods accept agent.Authorized as the first parameter after
// ctx. Authorized values can only be constructed by agent.Authorize and
// they encode (caller, action) at compile time, so a handler that bypasses
// the capability check fails to compile, not at runtime.
//
// Store holds a reference to an artifact.Store because Complete must
// insert the response message, insert the artifact, and transition the
// task state all in one transaction — the
// trg_tasks_completion_requires_outputs trigger fires on the state
// UPDATE and will reject the transition unless both child rows are
// visible in the same tx.
//
// CALLER CONTRACT: Submit and Complete perform multi-step writes and
// require the caller to supply a tx-bound Store via WithTx(tx). The
// MCP entry points (internal/mcp/commitment.go and a2a.go) wrap calls
// in withActorTx which opens a pgx.Tx, binds koopa.actor, and passes
// it down. Admin HTTP callers use ActorMiddleware. On a pool-backed
// Store these methods still work but are NOT atomic — a failure
// between child-row inserts and the state UPDATE leaves the task in a
// half-written state that the completion trigger will reject on
// retry.
type Store struct {
	q         *db.Queries
	artifacts *artifact.Store
}

// NewStore returns a Store backed by the given DBTX and artifact store.
// The artifact store is required for Complete's atomic path.
func NewStore(dbtx db.DBTX, artifacts *artifact.Store) *Store {
	return &Store{q: db.New(dbtx), artifacts: artifacts}
}

// WithTx returns a Store bound to tx for all queries. Used by callers
// composing multi-store transactions — typically via api.ActorMiddleware
// (HTTP) or mcp.Server.withActorTx (MCP). The tx carries koopa.actor
// so audit triggers attribute mutations correctly. The artifact store
// is rebound to the same tx so Complete's atomic path stays coherent.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	var arts *artifact.Store
	if s.artifacts != nil {
		arts = s.artifacts.WithTx(tx)
	}
	return &Store{q: s.q.WithTx(tx), artifacts: arts}
}

// Submit creates a new task in the submitted state and writes the initial
// request message. The two writes MUST be atomic — a task always has at
// least one request message, enforced by both caller contract and the
// completion trigger on task state transitions.
//
// The auth parameter MUST encode ActionSubmitTask. Callers obtain it via
// agent.Authorize. Compile fails if any other action is used at the call
// site because Authorized's fields are unexported.
func (s *Store) Submit(ctx context.Context, auth agent.Authorized, in *SubmitInput) (*Task, error) {
	if err := mustHaveAction(auth, agent.ActionSubmitTask); err != nil {
		return nil, err
	}
	if err := validateParts(in.RequestParts, taskMessagePartsBound); err != nil {
		return nil, err
	}
	partsJSON, err := marshalParts(in.RequestParts)
	if err != nil {
		return nil, fmt.Errorf("submit: marshalling request parts: %w", err)
	}

	metadata := in.Metadata
	if metadata == nil {
		metadata = json.RawMessage("{}")
	}

	row, err := s.q.CreateTask(ctx, db.CreateTaskParams{
		CreatedBy: in.Source,
		Assignee:  in.Target,
		Title:     in.Title,
		Deadline:  in.Deadline,
		Priority:  in.Priority,
		Metadata:  metadata,
	})
	if err != nil {
		return nil, mapInsertErr("submit", err)
	}

	// New task has no concurrent appenders by construction, but acquire
	// the lock anyway so the code path matches AppendMessage / Complete
	// exactly — no implicit 'first message is safe' branch.
	if err := s.q.LockTaskForAppend(ctx, row.ID); err != nil {
		return nil, fmt.Errorf("submit: lock task: %w", err)
	}
	if _, err := s.q.AppendTaskMessage(ctx, db.AppendTaskMessageParams{
		TaskID: row.ID,
		Role:   db.MessageRole(RoleRequest),
		Parts:  partsJSON,
	}); err != nil {
		return nil, mapInsertErr("submit: append request message", err)
	}

	return rowToTask(&row), nil
}

// Accept transitions a submitted task to working. Idempotent in the sense
// that re-accepting an already-working task yields ErrConflict (the row
// was not updated because the WHERE clause does not match), letting the
// caller recognise the no-op without a separate read.
func (s *Store) Accept(ctx context.Context, auth agent.Authorized, id uuid.UUID) (*Task, error) {
	if err := mustHaveAction(auth, agent.ActionAcceptTask); err != nil {
		return nil, err
	}
	row, err := s.q.AcceptTask(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("accept: %w", err)
	}
	return rowToTask(&row), nil
}

// Cancel marks a task canceled. Allowed from submitted or working only;
// terminal states (completed, canceled) yield ErrConflict.
func (s *Store) Cancel(ctx context.Context, auth agent.Authorized, id uuid.UUID) (*Task, error) {
	if err := mustHaveAction(auth, agent.ActionCancelTask); err != nil {
		return nil, err
	}
	row, err := s.q.CancelTask(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("cancel: %w", err)
	}
	return rowToTask(&row), nil
}

// RequestRevision transitions a completed task to revision_requested.
// Only the source agent should call this after reviewing the deliverable.
func (s *Store) RequestRevision(ctx context.Context, auth agent.Authorized, id uuid.UUID) (*Task, error) {
	if err := mustHaveAction(auth, agent.ActionRequestRevision); err != nil {
		return nil, err
	}
	row, err := s.q.RequestRevisionTask(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("request revision: %w", err)
	}
	return rowToTask(&row), nil
}

// Reaccept transitions a revision_requested task back to working.
// The assignee picks up the revision. Clears completed_at and
// revision_requested_at so the task can be re-completed.
func (s *Store) Reaccept(ctx context.Context, auth agent.Authorized, id uuid.UUID) (*Task, error) {
	if err := mustHaveAction(auth, agent.ActionReacceptTask); err != nil {
		return nil, err
	}
	row, err := s.q.ReacceptTask(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("reaccept: %w", err)
	}
	return rowToTask(&row), nil
}

// Task returns a single task by ID.
func (s *Store) Task(ctx context.Context, id uuid.UUID) (*Task, error) {
	row, err := s.q.TaskByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("task by id %s: %w", id, err)
	}
	return rowToTask(&row), nil
}

// OpenForAssignee returns submitted+working tasks where assignee is the
// caller. limit must be positive.
func (s *Store) OpenForAssignee(ctx context.Context, assignee string, limit int32) ([]Task, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%w: limit must be > 0", ErrInvalidInput)
	}
	rows, err := s.q.OpenTasksForAssignee(ctx, db.OpenTasksForAssigneeParams{
		Assignee:   assignee,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("open for assignee %s: %w", assignee, err)
	}
	out := make([]Task, len(rows))
	for i := range rows {
		out[i] = *rowToTask(&rows[i])
	}
	return out, nil
}

// OpenForCreator returns submitted+working tasks the caller created.
func (s *Store) OpenForCreator(ctx context.Context, creator string, limit int32) ([]Task, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%w: limit must be > 0", ErrInvalidInput)
	}
	rows, err := s.q.OpenTasksForCreator(ctx, db.OpenTasksForCreatorParams{
		CreatedBy:  creator,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("open for creator %s: %w", creator, err)
	}
	out := make([]Task, len(rows))
	for i := range rows {
		out[i] = *rowToTask(&rows[i])
	}
	return out, nil
}

// Open returns all submitted+working tasks across all agents. Used by
// admin-level aggregate views (studio overview). limit must be positive.
func (s *Store) Open(ctx context.Context, limit int32) ([]Task, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%w: limit must be > 0", ErrInvalidInput)
	}
	rows, err := s.q.AllOpenTasks(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("all open tasks: %w", err)
	}
	out := make([]Task, len(rows))
	for i := range rows {
		out[i] = *rowToTask(&rows[i])
	}
	return out, nil
}

// RecentResolved returns recently completed or canceled tasks. Used by
// admin-level aggregate views when include_resolved is requested.
// limit must be positive.
func (s *Store) RecentResolved(ctx context.Context, limit int32) ([]Task, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%w: limit must be > 0", ErrInvalidInput)
	}
	rows, err := s.q.RecentResolvedTasks(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("recent resolved tasks: %w", err)
	}
	out := make([]Task, len(rows))
	for i := range rows {
		out[i] = *rowToTask(&rows[i])
	}
	return out, nil
}

// Messages returns every message on a task in conversation order.
func (s *Store) Messages(ctx context.Context, taskID uuid.UUID) ([]Message, error) {
	rows, err := s.q.TaskMessages(ctx, taskID)
	if err != nil {
		return nil, fmt.Errorf("messages for task %s: %w", taskID, err)
	}
	out := make([]Message, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		parts, err := unmarshalParts(r.Parts)
		if err != nil {
			return nil, fmt.Errorf("messages: row %d: %w", i, err)
		}
		out = append(out, Message{
			ID:        r.ID,
			TaskID:    r.TaskID,
			Role:      Role(r.Role),
			Position:  r.Position,
			Parts:     parts,
			CreatedAt: r.CreatedAt,
		})
	}
	return out, nil
}

// TasksPaged returns a paginated list of tasks with optional state filter.
func (s *Store) TasksPaged(ctx context.Context, state *State, page, perPage int) ([]Task, int, error) {
	stateArg := db.NullTaskState{}
	if state != nil {
		stateArg.TaskState = db.TaskState(*state)
		stateArg.Valid = true
	}

	total, err := s.q.TasksPagedCount(ctx, stateArg)
	if err != nil {
		return nil, 0, fmt.Errorf("counting tasks: %w", err)
	}

	offset := (page - 1) * perPage
	rows, err := s.q.TasksPaged(ctx, db.TasksPagedParams{
		State:      stateArg,
		PageLimit:  int32(perPage), //nolint:gosec // G115: clamped by api.ParsePagination (max 100)
		PageOffset: int32(offset),  //nolint:gosec // G115: page*perPage bounded by pagination limits
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing tasks paged: %w", err)
	}
	out := make([]Task, len(rows))
	for i := range rows {
		out[i] = *rowToTask(&rows[i])
	}
	return out, int(total), nil
}

// OpenPaged returns paginated open tasks (submitted + working + revision_requested).
func (s *Store) OpenPaged(ctx context.Context, page, perPage int) ([]Task, int, error) {
	total, err := s.q.OpenTasksPagedCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("counting open tasks: %w", err)
	}

	offset := (page - 1) * perPage
	rows, err := s.q.OpenTasksPaged(ctx, db.OpenTasksPagedParams{
		PageLimit:  int32(perPage), //nolint:gosec // G115: clamped by api.ParsePagination (max 100)
		PageOffset: int32(offset),  //nolint:gosec // G115: page*perPage bounded by pagination limits
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing open tasks paged: %w", err)
	}
	out := make([]Task, len(rows))
	for i := range rows {
		out[i] = *rowToTask(&rows[i])
	}
	return out, int(total), nil
}

// CompletedPaged returns paginated completed tasks.
func (s *Store) CompletedPaged(ctx context.Context, page, perPage int) ([]Task, int, error) {
	total, err := s.q.CompletedTasksPagedCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("counting completed tasks: %w", err)
	}

	offset := (page - 1) * perPage
	rows, err := s.q.CompletedTasksPaged(ctx, db.CompletedTasksPagedParams{
		PageLimit:  int32(perPage), //nolint:gosec // G115: clamped by api.ParsePagination (max 100)
		PageOffset: int32(offset),  //nolint:gosec // G115: page*perPage bounded by pagination limits
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing completed tasks paged: %w", err)
	}
	out := make([]Task, len(rows))
	for i := range rows {
		out[i] = *rowToTask(&rows[i])
	}
	return out, int(total), nil
}

// AppendMessage adds a message to a task's conversation thread. Position
// is computed from the current message count. This method does not require
// agent.Authorized because the admin handler gates access via JWT middleware
// and message appending is not a state transition.
func (s *Store) AppendMessage(ctx context.Context, taskID uuid.UUID, role Role, parts []*a2a.Part) (*Message, error) {
	if err := validateParts(parts, taskMessagePartsBound); err != nil {
		return nil, err
	}
	partsJSON, err := marshalParts(parts)
	if err != nil {
		return nil, fmt.Errorf("append message: marshalling parts: %w", err)
	}

	// Lock the parent task row before reading MAX(position); caller's
	// tx scope ensures both statements run on the same connection.
	if err := s.q.LockTaskForAppend(ctx, taskID); err != nil {
		return nil, fmt.Errorf("append message: lock task: %w", err)
	}
	row, err := s.q.AppendTaskMessage(ctx, db.AppendTaskMessageParams{
		TaskID: taskID,
		Role:   db.MessageRole(role),
		Parts:  partsJSON,
	})
	if err != nil {
		return nil, mapInsertErr("append message", err)
	}

	msgParts, err := unmarshalParts(row.Parts)
	if err != nil {
		return nil, fmt.Errorf("append message: %w", err)
	}
	return &Message{
		ID:        row.ID,
		TaskID:    row.TaskID,
		Role:      Role(row.Role),
		Position:  row.Position,
		Parts:     msgParts,
		CreatedAt: row.CreatedAt,
	}, nil
}

// --- helpers ---

func rowToTask(r *db.Task) *Task {
	return &Task{
		ID:                  r.ID,
		Source:              r.CreatedBy,
		Target:              r.Assignee,
		Title:               r.Title,
		State:               State(r.State),
		Deadline:            r.Deadline,
		Priority:            r.Priority,
		SubmittedAt:         r.SubmittedAt,
		AcceptedAt:          r.AcceptedAt,
		CompletedAt:         r.CompletedAt,
		CanceledAt:          r.CanceledAt,
		RevisionRequestedAt: r.RevisionRequestedAt,
		Metadata:            r.Metadata,
	}
}

func marshalParts(parts []*a2a.Part) ([]byte, error) {
	if parts == nil {
		parts = []*a2a.Part{}
	}
	return json.Marshal(parts)
}

func unmarshalParts(b []byte) ([]*a2a.Part, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var out []*a2a.Part
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("unmarshal a2a parts: %w", err)
	}
	return out, nil
}

// partsBound expresses the per-table size cap on a JSONB parts array.
type partsBound struct {
	maxCount int
	maxBytes int
}

// taskMessagePartsBound matches chk_task_messages_parts_count (1..16) +
// chk_task_messages_parts_size (≤32 KB).
var taskMessagePartsBound = partsBound{maxCount: 16, maxBytes: 32 * 1024}

// artifactPartsBound matches chk_artifacts_parts_count (1..32) +
// chk_artifacts_parts_size (≤256 KB).
var artifactPartsBound = partsBound{maxCount: 32, maxBytes: 256 * 1024}

func validateParts(parts []*a2a.Part, b partsBound) error {
	if len(parts) == 0 {
		return fmt.Errorf("%w: parts is empty", ErrInvalidInput)
	}
	if len(parts) > b.maxCount {
		return fmt.Errorf("%w: parts count %d exceeds max %d", ErrInvalidInput, len(parts), b.maxCount)
	}
	// We don't pre-marshal here to estimate bytes; the DB CHECK is the
	// authoritative bound. Pre-checking would double-marshal in the happy path.
	return nil
}

func mustHaveAction(auth agent.Authorized, want agent.Action) error {
	if auth.Action() != want {
		return fmt.Errorf("%w: expected %s authorization, got %s", ErrInvalidInput, want, auth.Action())
	}
	return nil
}

// mapInsertErr translates raw pg errors into the package's sentinel set.
// Centralised so every Insert/Update path uses the same classification.
//
// Sentinel-only wrapping: pgErr.Message / ConstraintName carry schema detail
// (UUIDs, table names, trigger internals) that must not leak to MCP callers.
// Callers branch on the sentinel via errors.Is; infrastructure operators read
// full details from server-side slog.
func mapInsertErr(op string, err error) error {
	if err == nil {
		return nil
	}
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		switch pgErr.Code {
		case pgerrcode.UniqueViolation:
			return fmt.Errorf("%w: %s", ErrConflict, op)
		case pgerrcode.CheckViolation:
			return fmt.Errorf("%w: %s", ErrInvalidInput, op)
		case pgerrcode.RaiseException:
			return fmt.Errorf("%w: %s", ErrCompletionOutputsMissing, op)
		}
	}
	return fmt.Errorf("%s: %w", op, err)
}
