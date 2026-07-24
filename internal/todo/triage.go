// Copyright 2026 Koopa. All rights reserved.

// triage.go owns the owner-triage store surface consumed by the list_inbox
// and triage_todo MCP tools: the cross-creator inbox queue read, the
// FOR UPDATE state lock that gates a verdict, and the accept promotion.
// Unlike the *ByCreator readback surface these are deliberately unscoped —
// they execute the owner's verdict on any creator's todo, not caller
// self-cleanup.

package todo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa/internal/db"
)

// InboxEntry is the owner-triage projection for the list_inbox readback:
// enough to present a triage queue row — who captured it, when, and the
// captured description. Description is never NULL in the schema
// (TEXT NOT NULL DEFAULT ''), so an absent description reads as "".
type InboxEntry struct {
	ID          uuid.UUID
	Title       string
	Description string
	CreatedBy   string
	CreatedAt   time.Time
}

// InboxItems returns every todo in inbox state regardless of creator,
// oldest first. It backs the list_inbox MCP tool — the read half of the
// owner triage loop — and is deliberately cross-creator: the queue it reads
// is the owner's, not the caller's.
func (s *Store) InboxItems(ctx context.Context) ([]InboxEntry, error) {
	rows, err := s.q.InboxTodos(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing inbox todos: %w", err)
	}
	items := make([]InboxEntry, len(rows))
	for i := range rows {
		items[i] = InboxEntry{
			ID:          rows[i].ID,
			Title:       rows[i].Title,
			Description: rows[i].Description,
			CreatedBy:   rows[i].CreatedBy,
			CreatedAt:   rows[i].CreatedAt,
		}
	}
	return items, nil
}

// StateForUpdate returns a todo's current state while holding a row lock
// for the remainder of the surrounding transaction, so a transition
// validated in Go cannot race a concurrent state change. Must run on a
// transaction-bound Store (WithTx); an unknown id returns ErrNotFound.
func (s *Store) StateForUpdate(ctx context.Context, id uuid.UUID) (State, error) {
	state, err := s.q.TodoStateForUpdate(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("locking todo %s: %w", id, err)
	}
	return State(state), nil
}

// TriageAcceptParams holds accept's optional overrides. A nil field
// preserves the value captured on the row.
type TriageAcceptParams struct {
	ProjectID *uuid.UUID
	Due       *time.Time
	Energy    *string
}

// TriageAccept executes the owner's accept verdict: it promotes a todo to
// todo state, applying any overrides and preserving captured values for
// nil ones. Recurrence columns are untouched. Deliberately unscoped — the
// caller validates the inbox source state under StateForUpdate's lock in
// the same transaction. A vanished project override surfaces as
// ErrInvalidInput via the todos_project_id_fkey mapping.
func (s *Store) TriageAccept(ctx context.Context, id uuid.UUID, p *TriageAcceptParams) (*Item, error) {
	r, err := s.q.TriageAcceptTodo(ctx, db.TriageAcceptTodoParams{
		ID:        id,
		ProjectID: p.ProjectID,
		Due:       p.Due,
		Energy:    p.Energy,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapWriteError(err, fmt.Sprintf("accepting todo %s", id))
	}
	t := rowToItem(&r)
	return &t, nil
}
