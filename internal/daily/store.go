// store.go holds Store methods for daily_plan_items.
//
// Naming quirks worth knowing before adding callers:
//   - Create and Upsert both call sqlc's CreateItem query, which uses
//     ON CONFLICT DO UPDATE on (plan_date, todo_id). Upsert is the
//     honest name; Create is a legacy alias. New callers should use
//     Upsert.
//   - ItemsByDate returns Items with denormalised todo + project
//     fields for the list view; ItemByID returns the bare row.
//     The two converters (rawToItem vs itemsByDateRowToItem) reflect
//     this split.
//   - DeletePlannedByDate removes only items still in 'planned' state,
//     preserving done/deferred/dropped as historical record — the
//     safe "re-plan today" reset.

package daily

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
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

// Create inserts or upserts a daily plan item.
func (s *Store) Create(ctx context.Context, p *CreateItemParams) (*Item, error) {
	row, err := s.q.CreateItem(ctx, db.CreateItemParams{
		PlanDate:    p.PlanDate,
		TodoID:      p.TodoID,
		SelectedBy:  p.SelectedBy,
		Position:    p.Position,
		Reason:      p.Reason,
		AgentNoteID: p.AgentNoteID,
	})
	if err != nil {
		return nil, fmt.Errorf("creating daily plan item: %w", err)
	}
	return rawToItem(&row), nil
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

// UpdateStatus updates the status of a daily plan item.
func (s *Store) UpdateStatus(ctx context.Context, id uuid.UUID, status Status) error {
	_, err := s.q.UpdateItemStatus(ctx, db.UpdateItemStatusParams{
		ID:     id,
		Status: string(status),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("updating daily plan item status: %w", err)
	}
	return nil
}

// CompleteByTodo marks the daily plan item for a todo on a given date as done.
// Returns true if a matching plan item was found and updated.
func (s *Store) CompleteByTodo(ctx context.Context, todoItemID uuid.UUID, date time.Time) (bool, error) {
	n, err := s.q.UpdateItemStatusByTodo(ctx, db.UpdateItemStatusByTodoParams{
		TodoID:   todoItemID,
		PlanDate: date,
		Status:   string(StatusDone),
	})
	if err != nil {
		return false, fmt.Errorf("completing daily plan item by todo item: %w", err)
	}
	return n > 0, nil
}

// Upsert inserts or updates a daily plan item (upsert on plan_date + todo_id).
func (s *Store) Upsert(ctx context.Context, p *UpsertParams) (*Item, error) {
	row, err := s.q.CreateItem(ctx, db.CreateItemParams{
		PlanDate:    p.PlanDate,
		TodoID:      p.TodoID,
		SelectedBy:  p.SelectedBy,
		Position:    p.Position,
		Reason:      p.Reason,
		AgentNoteID: p.AgentNoteID,
	})
	if err != nil {
		return nil, fmt.Errorf("upserting daily plan item: %w", err)
	}
	return rawToItem(&row), nil
}

// Complete marks a daily plan item as done.
func (s *Store) Complete(ctx context.Context, id uuid.UUID) error {
	return s.UpdateStatus(ctx, id, StatusDone)
}

// Defer marks a daily plan item as deferred.
func (s *Store) Defer(ctx context.Context, id uuid.UUID) error {
	return s.UpdateStatus(ctx, id, StatusDeferred)
}

// Drop marks a daily plan item as dropped.
func (s *Store) Drop(ctx context.Context, id uuid.UUID) error {
	return s.UpdateStatus(ctx, id, StatusDropped)
}

// ItemByID returns a single daily plan item by ID (without todo item joins).
func (s *Store) ItemByID(ctx context.Context, id uuid.UUID) (*Item, error) {
	r, err := s.q.ItemByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying daily plan item %s: %w", id, err)
	}
	return rawToItem(&r), nil
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
		ID:          r.ID,
		PlanDate:    r.PlanDate,
		TodoID:      r.TodoID,
		SelectedBy:  r.SelectedBy,
		Position:    r.Position,
		Reason:      r.Reason,
		AgentNoteID: r.AgentNoteID,
		Status:      Status(r.Status),
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func itemsByDateRowToItem(r *db.ItemsByDateRow) Item {
	return Item{
		ID:           r.ID,
		PlanDate:     r.PlanDate,
		TodoID:       r.TodoID,
		SelectedBy:   r.SelectedBy,
		Position:     r.Position,
		Reason:       r.Reason,
		AgentNoteID:  r.AgentNoteID,
		Status:       Status(r.Status),
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
		TodoTitle:    r.TodoTitle,
		TodoState:    string(r.TodoState),
		TodoDue:      r.TodoDue,
		TodoEnergy:   r.TodoEnergy,
		TodoPriority: r.TodoPriority,
		ProjectTitle: r.ProjectTitle,
		ProjectSlug:  r.ProjectSlug,
	}
}
