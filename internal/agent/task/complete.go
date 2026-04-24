package task

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/agent/artifact"
	"github.com/Koopa0/koopa/internal/db"
)

// validateCompleteInput runs the pre-tx checks for Complete. Split out so the
// main function stays under the cyclomatic budget.
func (s *Store) validateCompleteInput(auth agent.Authorized, in *CompleteInput) error {
	if err := mustHaveAction(auth, agent.ActionCompleteTask); err != nil {
		return err
	}
	if err := validateParts(in.ResponseParts, taskMessagePartsBound); err != nil {
		return fmt.Errorf("complete: response: %w", err)
	}
	if err := validateParts(in.ArtifactParts, artifactPartsBound); err != nil {
		return fmt.Errorf("complete: artifact: %w", err)
	}
	if in.ArtifactName == "" {
		return fmt.Errorf("%w: artifact name required", ErrInvalidInput)
	}
	if s.artifacts == nil {
		return errors.New("task: Complete requires an artifact store; construct task.Store via NewStore")
	}
	return nil
}

// Complete is the atomic completion path: append a response message,
// insert an artifact, transition state to completed — all three writes
// MUST land in the same transaction so the
// trg_tasks_completion_requires_outputs trigger sees both child rows
// when the state UPDATE fires. There is no other public path to
// completion; exposing the three operations separately would let a
// caller orchestrate them wrong and trip the trigger at runtime.
//
// CALLER CONTRACT: supply a tx-bound Store via WithTx(tx). The MCP
// entry point (file_report in internal/mcp/a2a.go) wraps in
// withActorTx; admin HTTP uses ActorMiddleware. A pool-backed Store
// will either trip the completion trigger (when the state UPDATE runs
// on a fresh connection without the child rows yet visible) or — worse
// — partially commit and leave the task in an illegal state.
//
// The auth parameter MUST encode ActionCompleteTask. artifact.Store.Add
// accepts ActionCompleteTask as a proxy for ActionPublishArtifact
// (both map to the PublishArtifacts capability bit), so the caller does
// not need to re-authorize for the artifact insert.
func (s *Store) Complete(ctx context.Context, auth agent.Authorized, in *CompleteInput) (*Task, error) {
	if err := s.validateCompleteInput(auth, in); err != nil {
		return nil, err
	}

	respJSON, err := marshalParts(in.ResponseParts)
	if err != nil {
		return nil, fmt.Errorf("complete: marshal response parts: %w", err)
	}

	// Lock the parent task row before reading MAX(position); this tx
	// is caller-supplied (via withActorTx), so the lock scope covers
	// the MAX read and INSERT.
	if err := s.q.LockTaskForAppend(ctx, in.TaskID); err != nil {
		return nil, fmt.Errorf("complete: lock task: %w", err)
	}
	if _, err := s.q.AppendTaskMessage(ctx, db.AppendTaskMessageParams{
		TaskID: in.TaskID,
		Role:   db.MessageRole(RoleResponse),
		Parts:  respJSON,
	}); err != nil {
		return nil, mapInsertErr("complete: append response", err)
	}

	// s.artifacts is already tx-bound when the caller constructed this
	// Store via WithTx(tx) — task.Store.WithTx rebinds s.artifacts to
	// the same tx so the artifact INSERT is visible to the completion
	// trigger when the state UPDATE fires below.
	if _, err := s.artifacts.Add(ctx, auth, artifact.AddInput{
		TaskID:      &in.TaskID,
		Name:        in.ArtifactName,
		Description: in.ArtifactDesc,
		Parts:       in.ArtifactParts,
	}); err != nil {
		return nil, fmt.Errorf("complete: add artifact: %w", err)
	}

	row, err := s.q.TransitionTaskToCompleted(ctx, in.TaskID)
	if err != nil {
		// trg_tasks_completion_requires_outputs raises P0001. This should
		// not actually fire in normal usage because we just inserted both
		// child rows; if it does, surface the dedicated sentinel so
		// handlers can branch.
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.RaiseException {
			return nil, fmt.Errorf("%w: %s", ErrCompletionOutputsMissing, pgErr.Message)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("complete: transition: %w", err)
	}

	return rowToTask(&row), nil
}
