package daily

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
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
		PlanDate:   p.PlanDate,
		TaskID:     p.TaskID,
		SelectedBy: p.SelectedBy,
		Position:   p.Position,
		Reason:     p.Reason,
		JournalID:  p.JournalID,
	})
	if err != nil {
		return nil, fmt.Errorf("creating daily plan item: %w", err)
	}
	return rawToItem(&row), nil
}

// ItemsByDate returns all plan items for a specific date with task details.
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

// CompleteByTask marks the daily plan item for a task on a given date as done.
func (s *Store) CompleteByTask(ctx context.Context, taskID uuid.UUID, date time.Time) error {
	return s.q.UpdateItemStatusByTask(ctx, db.UpdateItemStatusByTaskParams{
		TaskID:   taskID,
		PlanDate: date,
		Status:   string(StatusDone),
	})
}

// Upsert inserts or updates a daily plan item (upsert on plan_date + task_id).
func (s *Store) Upsert(ctx context.Context, p *UpsertParams) (*Item, error) {
	row, err := s.q.CreateItem(ctx, db.CreateItemParams{
		PlanDate:   p.PlanDate,
		TaskID:     p.TaskID,
		SelectedBy: p.SelectedBy,
		Position:   p.Position,
		Reason:     p.Reason,
		JournalID:  p.JournalID,
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

// ItemByID returns a single daily plan item by ID (without task joins).
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
// Preserves done/deferred/dropped items as historical records.
func (s *Store) DeletePlannedByDate(ctx context.Context, date time.Time) error {
	return s.q.DeletePlannedItemsByDate(ctx, date)
}

func rawToItem(r *db.DailyPlanItem) *Item {
	return &Item{
		ID:         r.ID,
		PlanDate:   r.PlanDate,
		TaskID:     r.TaskID,
		SelectedBy: r.SelectedBy,
		Position:   r.Position,
		Reason:     r.Reason,
		JournalID:  r.JournalID,
		Status:     Status(r.Status),
		CreatedAt:  r.CreatedAt,
		UpdatedAt:  r.UpdatedAt,
	}
}

func itemsByDateRowToItem(r *db.ItemsByDateRow) Item {
	return Item{
		ID:           r.ID,
		PlanDate:     r.PlanDate,
		TaskID:       r.TaskID,
		SelectedBy:   r.SelectedBy,
		Position:     r.Position,
		Reason:       r.Reason,
		JournalID:    r.JournalID,
		Status:       Status(r.Status),
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
		TaskTitle:    r.TaskTitle,
		TaskStatus:   string(r.TaskStatus),
		TaskDue:      r.TaskDue,
		TaskEnergy:   r.TaskEnergy,
		TaskPriority: r.TaskPriority,
		TaskAssignee: r.TaskAssignee,
		ProjectTitle: r.ProjectTitle,
		ProjectSlug:  r.ProjectSlug,
	}
}
