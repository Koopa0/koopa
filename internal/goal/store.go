package goal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles database operations for goals.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// Goals returns all goals ordered by status and deadline.
func (s *Store) Goals(ctx context.Context) ([]Goal, error) {
	rows, err := s.q.Goals(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing goals: %w", err)
	}
	goals := make([]Goal, len(rows))
	for i := range rows {
		r := rows[i]
		goals[i] = rowToGoal(&r)
	}
	return goals, nil
}

// GoalByTitle returns a goal by case-insensitive title match.
func (s *Store) GoalByTitle(ctx context.Context, title string) (*Goal, error) {
	r, err := s.q.GoalByTitle(ctx, title)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying goal by title %q: %w", title, err)
	}
	g := rowToGoal(&r)
	return &g, nil
}

// UpdateStatus updates a goal's status.
func (s *Store) UpdateStatus(ctx context.Context, id uuid.UUID, status Status) (*Goal, error) {
	r, err := s.q.UpdateGoalStatus(ctx, db.UpdateGoalStatusParams{
		ID:     id,
		Status: db.GoalStatus(status),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating goal %s status: %w", id, err)
	}
	g := rowToGoal(&r)
	return &g, nil
}

// CreateGoal inserts a new goal.
func (s *Store) CreateGoal(ctx context.Context, title, description, status string, areaID *uuid.UUID, quarter *string, deadline *time.Time) (*Goal, error) {
	r, err := s.q.CreateGoal(ctx, db.CreateGoalParams{
		Title:       title,
		Description: description,
		Status:      db.GoalStatus(status),
		AreaID:      areaID,
		Quarter:     quarter,
		Deadline:    deadline,
	})
	if err != nil {
		return nil, fmt.Errorf("creating goal: %w", err)
	}
	g := rowToGoal(&r)
	return &g, nil
}

// GoalByID returns a single goal by ID.
func (s *Store) GoalByID(ctx context.Context, id uuid.UUID) (*Goal, error) {
	r, err := s.q.GoalByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying goal %s: %w", id, err)
	}
	g := rowToGoal(&r)
	return &g, nil
}

// Milestone represents a goal milestone.
type Milestone struct {
	ID             uuid.UUID  `json:"id"`
	GoalID         uuid.UUID  `json:"goal_id"`
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	TargetDeadline *time.Time `json:"target_deadline,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// CreateMilestone inserts a new milestone under a goal.
func (s *Store) CreateMilestone(ctx context.Context, goalID uuid.UUID, title, description string, targetDeadline *time.Time) (*Milestone, error) {
	r, err := s.q.CreateMilestone(ctx, db.CreateMilestoneParams{
		GoalID:         goalID,
		Title:          title,
		Description:    description,
		TargetDeadline: targetDeadline,
	})
	if err != nil {
		return nil, fmt.Errorf("creating milestone: %w", err)
	}
	return &Milestone{
		ID:             r.ID,
		GoalID:         r.GoalID,
		Title:          r.Title,
		Description:    r.Description,
		TargetDeadline: r.TargetDeadline,
		CompletedAt:    r.CompletedAt,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
	}, nil
}

// ActiveGoalSummary represents an active goal with milestone progress.
type ActiveGoalSummary struct {
	Goal
	AreaName       string `json:"area_name"`
	MilestoneTotal int64  `json:"milestone_total"`
	MilestoneDone  int64  `json:"milestone_done"`
}

// ActiveGoals returns in-progress goals with milestone counts.
func (s *Store) ActiveGoals(ctx context.Context) ([]ActiveGoalSummary, error) {
	rows, err := s.q.ActiveGoals(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying active goals: %w", err)
	}
	result := make([]ActiveGoalSummary, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = ActiveGoalSummary{
			Goal: Goal{
				ID:          r.ID,
				Title:       r.Title,
				Description: r.Description,
				Status:      Status(r.Status),
				AreaID:      r.AreaID,
				Quarter:     r.Quarter,
				Deadline:    r.Deadline,
				CreatedAt:   r.CreatedAt,
				UpdatedAt:   r.UpdatedAt,
			},
			AreaName:       r.AreaName,
			MilestoneTotal: r.MilestoneTotal,
			MilestoneDone:  r.MilestoneDone,
		}
	}
	return result, nil
}

func rowToGoal(r *db.Goal) Goal {
	return Goal{
		ID:           r.ID,
		Title:        r.Title,
		Description:  r.Description,
		Status:       Status(r.Status),
		AreaID:       r.AreaID,
		Quarter:      r.Quarter,
		Deadline:     r.Deadline,
		NotionPageID: r.NotionPageID,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}
}
