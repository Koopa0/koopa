// recurring.go owns recurrence semantics for todos. Completing a
// recurring todo fires RecurringDoneHandler which schedules the next
// cycle; OverdueRecurringItems / RecurringItemsDueToday feed the
// daily-plan reader. Recurrence math (intervals, units, month-clamping)
// is in todo.go so it can be reused by non-recurring due-date queries.

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

// SetRecurringDoneHandler registers the callback for recurring todo completion.
func (s *Store) SetRecurringDoneHandler(h RecurringDoneHandler) {
	s.recurringDoneHandler = h
}

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

// ResetRecurring advances a recurring todo item's due date and resets state to todo.
func (s *Store) ResetRecurring(ctx context.Context, id uuid.UUID, nextDue time.Time) (*Item, error) {
	r, err := s.q.ResetRecurringTodoItem(ctx, db.ResetRecurringTodoItemParams{ID: id, Due: &nextDue})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("resetting recurring todo item %s: %w", id, err)
	}
	t := rowToItem(&r)
	return &t, nil
}

// LogSkip inserts a skip record.
func (s *Store) LogSkip(ctx context.Context, itemID uuid.UUID, originalDue, skippedDate time.Time, reason string) error {
	return s.q.CreateTodoSkipRecord(ctx, db.CreateTodoSkipRecordParams{
		TodoID:      itemID,
		OriginalDue: originalDue,
		SkippedDate: skippedDate,
		Reason:      reason,
	})
}

// RecurringItemByProject finds a recurring pending todo item under a project due today or overdue.
func (s *Store) RecurringItemByProject(ctx context.Context, projectID uuid.UUID, today time.Time) (*Item, error) {
	r, err := s.q.RecurringTodoItemByProject(ctx, db.RecurringTodoItemByProjectParams{
		ProjectID: &projectID,
		Today:     &today,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("querying recurring todo item for project %s: %w", projectID, err)
	}
	t := rowToItem(&r)
	return &t, nil
}
