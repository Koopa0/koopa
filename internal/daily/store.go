// Copyright 2026 Koopa. All rights reserved.

// store.go holds Store methods for daily_plan_items.
//
// Naming quirks worth knowing before adding callers:
//   - CreateAll upserts a whole plan's items in one round trip
//     (pgx.Batch, via sqlc's CreateItem :batchone query) on
//     (plan_date, todo_id); each item's result independently reports
//     ErrItemResolved when that row is already in a terminal state.
//   - ItemsByDate returns Items with denormalised todo + project
//     fields for the list view via itemsByDateRowToItem; CreateAll
//     returns the bare row via rawToItem.
//   - DeletePlannedByDate removes only items still in 'planned' state,
//     preserving done/deferred/dropped as historical record — the
//     safe "re-plan today" reset.

package daily

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa/internal/db"
)

// Store handles database operations for daily plan items.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// CreateResult is one item's outcome from Store.CreateAll, index-aligned
// with the input slice. Err is ErrItemResolved when that item's row already
// reached a terminal state (re-planning must not resurrect it), or a
// wrapped infrastructure error; Item is non-nil exactly when Err is nil.
type CreateResult struct {
	Item *Item
	Err  error
}

// CreateAll inserts a whole plan's worth of items in one round trip,
// upserting on (plan_date, todo_id): pgx.Batch pipelines the N executions
// instead of N sequential round trips. Each item's outcome is independent —
// one item's ErrItemResolved (its row already reached a terminal state)
// does not affect any other item's result.
func (s *Store) CreateAll(ctx context.Context, items []CreateItemParams) []CreateResult {
	params := make([]db.CreateItemParams, len(items))
	for i := range items {
		params[i] = db.CreateItemParams{
			PlanDate:   items[i].PlanDate,
			TodoID:     items[i].TodoID,
			SelectedBy: items[i].SelectedBy,
			Position:   items[i].Position,
			Reason:     items[i].Reason,
		}
	}
	results := make([]CreateResult, len(items))
	s.q.CreateItem(ctx, params).QueryRow(func(i int, row db.DailyPlanItem, err error) {
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				results[i] = CreateResult{Err: ErrItemResolved}
				return
			}
			results[i] = CreateResult{Err: fmt.Errorf("creating daily plan item: %w", err)}
			return
		}
		results[i] = CreateResult{Item: rawToItem(&row)}
	})
	return results
}

// ItemsByDate returns all plan items for a specific date with todo item details.
func (s *Store) ItemsByDate(ctx context.Context, date time.Time) ([]Item, error) {
	rows, err := s.q.ItemsByDate(ctx, date)
	if err != nil {
		return nil, fmt.Errorf("querying daily plan items: %w", err)
	}
	items := make([]Item, len(rows))
	for i := range rows {
		items[i] = itemsByDateRowToItem(&rows[i])
	}
	return items, nil
}

// DeletePlannedByDate removes only 'planned' items for a date (re-planning).
// Preserves done/deferred/dropped items as historical records. Returns the
// removed rows (id + todo_id + title) so callers can surface "what was
// displaced" when plan_day idempotently replaces an existing plan.
func (s *Store) DeletePlannedByDate(ctx context.Context, date time.Time) ([]RemovedItem, error) {
	rows, err := s.q.DeletePlannedItemsByDate(ctx, date)
	if err != nil {
		return nil, fmt.Errorf("deleting planned items for %s: %w", date.Format(time.DateOnly), err)
	}
	out := make([]RemovedItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, RemovedItem{
			ID:        r.ID,
			TodoID:    r.TodoID,
			TodoTitle: r.TodoTitle,
		})
	}
	return out, nil
}

func rawToItem(r *db.DailyPlanItem) *Item {
	return &Item{
		ID:         r.ID,
		PlanDate:   r.PlanDate,
		TodoID:     r.TodoID,
		SelectedBy: r.SelectedBy,
		Position:   r.Position,
		Reason:     r.Reason,
		Status:     Status(r.Status),
		CreatedAt:  r.CreatedAt,
		UpdatedAt:  r.UpdatedAt,
	}
}

func itemsByDateRowToItem(r *db.ItemsByDateRow) Item {
	return Item{
		ID:                  r.ID,
		PlanDate:            r.PlanDate,
		TodoID:              r.TodoID,
		SelectedBy:          r.SelectedBy,
		Position:            r.Position,
		Reason:              r.Reason,
		Status:              Status(r.Status),
		CreatedAt:           r.CreatedAt,
		UpdatedAt:           r.UpdatedAt,
		TodoTitle:           r.TodoTitle,
		TodoState:           string(r.TodoState),
		TodoDue:             r.TodoDue,
		TodoEnergy:          r.TodoEnergy,
		TodoPriority:        r.TodoPriority,
		TodoRecurWeekdays:   r.TodoRecurWeekdays,
		TodoRecurInterval:   r.TodoRecurInterval,
		TodoLastCompletedOn: r.TodoLastCompletedOn,
		ProjectTitle:        r.ProjectTitle,
		ProjectSlug:         r.ProjectSlug,
	}
}
