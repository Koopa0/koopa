// Copyright 2026 Koopa. All rights reserved.

// recurring.go owns the recurring-todo read queries behind
// GET /api/admin/commitment/todos/recurring: OverdueRecurringItems and
// RecurringItemsDueToday feed the daily-plan reader (todo.Handler.Recurring).
// UpdateDue is the lone due-date write used by that surface.

package todo

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/db"
)

// OverdueRecurringItems returns recurring todo items with due < today.
func (s *Store) OverdueRecurringItems(ctx context.Context, today time.Time) ([]Item, error) {
	rows, err := s.q.OverdueRecurringTodoItems(ctx, &today)
	if err != nil {
		return nil, fmt.Errorf("listing overdue recurring todo items: %w", err)
	}
	items := make([]Item, len(rows))
	for i := range rows {
		items[i] = rowToItem(&rows[i])
	}
	return items, nil
}

// RecurringItemsDueToday returns recurring todo items due today.
func (s *Store) RecurringItemsDueToday(ctx context.Context, today time.Time) ([]Item, error) {
	rows, err := s.q.RecurringTodoItemsDueToday(ctx, &today)
	if err != nil {
		return nil, fmt.Errorf("listing recurring todo items due today: %w", err)
	}
	items := make([]Item, len(rows))
	for i := range rows {
		items[i] = rowToItem(&rows[i])
	}
	return items, nil
}

// UpdateDue updates only the due date.
func (s *Store) UpdateDue(ctx context.Context, id uuid.UUID, due time.Time) error {
	n, err := s.q.UpdateTodoItemDue(ctx, db.UpdateTodoItemDueParams{ID: id, Due: &due})
	if err != nil {
		return fmt.Errorf("updating todo item %s due: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
