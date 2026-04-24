package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/db"
)

// Store handles persistence for the artifacts table.
//
// Add takes agent.Authorized so the compile-time capability gate stops
// non-PublishArtifacts callers at the type system. Read paths are
// unauthenticated by design — listing artifacts is a query, the gate is
// the route the caller takes to reach the read.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given DBTX (pool or tx).
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a Store bound to the given transaction. Used by
// task.Store.Complete to insert the artifact row in the same tx as the
// response message append + state transition, so the
// trg_tasks_completion_requires_outputs trigger sees both children when
// the UPDATE fires.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// Add inserts a new artifact. When TaskID is non-nil the artifact is
// bound to that task; when nil it is a standalone (self-initiated)
// artifact and CreatedBy is required. Returns ErrInvalidInput when the
// parts payload violates the schema bounds (1..32 parts, ≤256 KB) or
// when the name is blank.
func (s *Store) Add(ctx context.Context, auth agent.Authorized, in AddInput) (*Artifact, error) {
	if err := mustHaveAction(auth, agent.ActionPublishArtifact); err != nil {
		return nil, err
	}
	if err := validateParts(in.Parts); err != nil {
		return nil, err
	}
	if in.Name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}

	partsJSON, err := marshalParts(in.Parts)
	if err != nil {
		return nil, fmt.Errorf("add: marshalling parts: %w", err)
	}

	row, err := s.q.InsertArtifact(ctx, db.InsertArtifactParams{
		TaskID:      in.TaskID,
		CreatedBy:   nilIfEmpty(in.CreatedBy),
		Name:        in.Name,
		Description: in.Description,
		Parts:       partsJSON,
	})
	if err != nil {
		return nil, mapInsertErr("add", err)
	}
	return toArtifact(row.ID, row.TaskID, row.CreatedBy, row.Name, row.Description, row.Parts, row.CreatedAt)
}

// Artifact returns a single artifact by ID.
func (s *Store) Artifact(ctx context.Context, id uuid.UUID) (*Artifact, error) {
	row, err := s.q.ArtifactByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("artifact by id %s: %w", id, err)
	}
	return toArtifact(row.ID, row.TaskID, row.CreatedBy, row.Name, row.Description, row.Parts, row.CreatedAt)
}

// ForTask returns all artifacts on a task in chronological order.
func (s *Store) ForTask(ctx context.Context, taskID uuid.UUID) ([]Artifact, error) {
	rows, err := s.q.ArtifactsForTask(ctx, &taskID)
	if err != nil {
		return nil, fmt.Errorf("artifacts for task %s: %w", taskID, err)
	}
	out := make([]Artifact, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		a, err := toArtifact(r.ID, r.TaskID, r.CreatedBy, r.Name, r.Description, r.Parts, r.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("artifacts for task %s: row %d: %w", taskID, i, err)
		}
		out = append(out, *a)
	}
	return out, nil
}

// CountForTask returns the number of artifacts attached to a task.
// Used by task.Store.Complete's atomic completion path to assert the
// trigger precondition holds before issuing the state UPDATE.
func (s *Store) CountForTask(ctx context.Context, taskID uuid.UUID) (int, error) {
	n, err := s.q.ArtifactCountForTask(ctx, &taskID)
	if err != nil {
		return 0, fmt.Errorf("artifact count for task %s: %w", taskID, err)
	}
	return int(n), nil
}

// Recent returns the most recent artifacts across all tasks. Used by
// admin-level aggregate views (studio overview). limit must be positive.
func (s *Store) Recent(ctx context.Context, limit int32) ([]Artifact, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%w: limit must be > 0", ErrInvalidInput)
	}
	rows, err := s.q.RecentArtifacts(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("recent artifacts: %w", err)
	}
	out := make([]Artifact, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		a, err := toArtifact(r.ID, r.TaskID, r.CreatedBy, r.Name, r.Description, r.Parts, r.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("recent artifacts: row %d: %w", i, err)
		}
		out = append(out, *a)
	}
	return out, nil
}

// --- helpers ---

func toArtifact(id uuid.UUID, taskID *uuid.UUID, createdBy *string, name, desc string, partsJSON []byte, createdAt time.Time) (*Artifact, error) {
	parts, err := unmarshalParts(partsJSON)
	if err != nil {
		return nil, fmt.Errorf("artifact %s: %w", id, err)
	}
	return &Artifact{
		ID:          id,
		TaskID:      taskID,
		CreatedBy:   createdBy,
		Name:        name,
		Description: desc,
		Parts:       parts,
		CreatedAt:   createdAt,
	}, nil
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

func validateParts(parts []*a2a.Part) error {
	if len(parts) == 0 {
		return fmt.Errorf("%w: parts is empty", ErrInvalidInput)
	}
	if len(parts) > 32 {
		return fmt.Errorf("%w: parts count %d exceeds max 32", ErrInvalidInput, len(parts))
	}
	return nil
}

// mustHaveAction permits both ActionPublishArtifact (direct add) and
// ActionCompleteTask (atomic completion via task.Store.Complete).
func mustHaveAction(auth agent.Authorized, want agent.Action) error {
	got := auth.Action()
	if got == want {
		return nil
	}
	if want == agent.ActionPublishArtifact && got == agent.ActionCompleteTask {
		return nil
	}
	return fmt.Errorf("%w: expected %s authorization, got %s", ErrInvalidInput, want, got)
}

func mapInsertErr(op string, err error) error {
	if err == nil {
		return nil
	}
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		switch pgErr.Code {
		case pgerrcode.CheckViolation:
			return fmt.Errorf("%w: %s: %s", ErrInvalidInput, op, pgErr.ConstraintName)
		case pgerrcode.ForeignKeyViolation:
			return fmt.Errorf("%w: %s: parent task missing", ErrInvalidInput, op)
		}
	}
	return fmt.Errorf("%s: %w", op, err)
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
