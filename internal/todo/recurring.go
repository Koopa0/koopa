// Copyright 2026 Koopa. All rights reserved.

// recurring.go owns the recurring-todo surface. RecurringItemsDueToday computes
// today's due occurrences on read — no stored next-due, no scheduler — for
// todo.Handler.Recurring and the morning brief. SetRecurrence sets or clears a
// todo's schedule. CompleteOccurrence stamps last_completed_on when a recurring
// occurrence is done, leaving the todo recurring rather than moving it to a
// terminal state.

package todo

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/db"
)

// RecurringItemsDueToday returns recurring todos whose occurrence is due on
// today, computed from the recurrence rule and last_completed_on (compute-on-
// read — see RecurringTodoItemsDueToday in query.sql).
func (s *Store) RecurringItemsDueToday(ctx context.Context, today time.Time) ([]Item, error) {
	rows, err := s.q.RecurringTodoItemsDueToday(ctx, today)
	if err != nil {
		return nil, fmt.Errorf("listing recurring todo items due today: %w", err)
	}
	items := make([]Item, len(rows))
	for i := range rows {
		items[i] = rowToItem(&rows[i])
	}
	return items, nil
}

// Recurrence is the schedule passed to SetRecurrence: weekday-mode (Weekdays
// non-nil) or interval-mode (Interval and Unit non-nil), or all-nil to clear.
// The caller validates the combination; chk_todo_recurrence is the backstop.
type Recurrence struct {
	Weekdays *int16
	Interval *int32
	Unit     *string
}

// SetRecurrence sets or clears a todo's recurrence, scoped to the caller's own
// todos (created_by). Returns ErrNotFound when no caller-owned todo matches.
func (s *Store) SetRecurrence(ctx context.Context, id uuid.UUID, createdBy string, r Recurrence) error {
	n, err := s.q.SetTodoRecurrence(ctx, db.SetTodoRecurrenceParams{
		ID:            id,
		CreatedBy:     createdBy,
		RecurWeekdays: r.Weekdays,
		RecurInterval: r.Interval,
		RecurUnit:     r.Unit,
	})
	if err != nil {
		return fmt.Errorf("setting recurrence for todo %s: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CompleteOccurrence stamps last_completed_on for today's occurrence of a
// recurring todo, scoped to the caller's own todos. The todo keeps recurring —
// no terminal state. Returns ErrNotFound when no recurring caller-owned todo
// matches.
func (s *Store) CompleteOccurrence(ctx context.Context, id uuid.UUID, createdBy string, completedOn time.Time) error {
	n, err := s.q.CompleteRecurringOccurrence(ctx, db.CompleteRecurringOccurrenceParams{
		ID:          id,
		CreatedBy:   createdBy,
		CompletedOn: completedOn,
	})
	if err != nil {
		return fmt.Errorf("completing recurring occurrence for todo %s: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
