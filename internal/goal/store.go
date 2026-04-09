package goal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

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
	Position       int32      `json:"position"`
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
	return rowToMilestone(&r), nil
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

// GoalWithArea is a goal with its area name resolved.
type GoalWithArea struct {
	Goal
	AreaName string `json:"area_name"`
}

// ByID returns a single goal by ID with area name resolved.
func (s *Store) ByID(ctx context.Context, id uuid.UUID) (*GoalWithArea, error) {
	r, err := s.q.GoalByIDWithArea(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying goal %s with area: %w", id, err)
	}
	return &GoalWithArea{
		Goal: Goal{
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
		},
		AreaName: r.AreaName,
	}, nil
}

// MilestonesByGoal returns milestones for a goal ordered by position.
func (s *Store) MilestonesByGoal(ctx context.Context, goalID uuid.UUID) ([]Milestone, error) {
	rows, err := s.q.MilestonesByGoal(ctx, goalID)
	if err != nil {
		return nil, fmt.Errorf("listing milestones for goal %s: %w", goalID, err)
	}
	milestones := make([]Milestone, len(rows))
	for i := range rows {
		r := &rows[i]
		milestones[i] = Milestone{
			ID:             r.ID,
			GoalID:         r.GoalID,
			Title:          r.Title,
			Description:    r.Description,
			TargetDeadline: r.TargetDeadline,
			CompletedAt:    r.CompletedAt,
			Position:       r.Position,
			CreatedAt:      r.CreatedAt,
			UpdatedAt:      r.UpdatedAt,
		}
	}
	return milestones, nil
}

// CreateParams holds the parameters for creating a new goal.
type CreateParams struct {
	Title       string
	Description string
	AreaID      *uuid.UUID
	Deadline    *time.Time
	Quarter     *string
}

// Create inserts a new goal with status=not-started.
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Goal, error) {
	r, err := s.q.CreateGoal(ctx, db.CreateGoalParams{
		Title:       p.Title,
		Description: p.Description,
		Status:      db.GoalStatusNotStarted,
		AreaID:      p.AreaID,
		Quarter:     p.Quarter,
		Deadline:    p.Deadline,
	})
	if err != nil {
		return nil, fmt.Errorf("creating goal: %w", err)
	}
	g := rowToGoal(&r)
	return &g, nil
}

// CreateMilestoneSimple inserts a new milestone with only title and position.
func (s *Store) CreateMilestoneSimple(ctx context.Context, goalID uuid.UUID, title string, position int32) (*Milestone, error) {
	r, err := s.q.CreateMilestoneWithPosition(ctx, db.CreateMilestoneWithPositionParams{
		GoalID:   goalID,
		Title:    title,
		Position: position,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating milestone: %w", err)
	}
	return &Milestone{
		ID:             r.ID,
		GoalID:         r.GoalID,
		Title:          r.Title,
		Description:    r.Description,
		TargetDeadline: r.TargetDeadline,
		CompletedAt:    r.CompletedAt,
		Position:       r.Position,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
	}, nil
}

// ToggleMilestone toggles a milestone's completed_at (set to now if null, null if set).
func (s *Store) ToggleMilestone(ctx context.Context, id uuid.UUID) (*Milestone, error) {
	r, err := s.q.ToggleMilestone(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("toggling milestone %s: %w", id, err)
	}
	return &Milestone{
		ID:             r.ID,
		GoalID:         r.GoalID,
		Title:          r.Title,
		Description:    r.Description,
		TargetDeadline: r.TargetDeadline,
		CompletedAt:    r.CompletedAt,
		Position:       r.Position,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
	}, nil
}

// ActivityType is a typed enum of goal activity sources.
type ActivityType string

const (
	ActivityMilestoneCompleted ActivityType = "milestone_completed"
	ActivityTaskCompleted      ActivityType = "task_completed"
	ActivityContentPublished   ActivityType = "content_published"
)

// ActivityItem is a single entry in a goal's recent activity timeline.
type ActivityItem struct {
	Type      ActivityType
	Title     string
	RefID     string
	RefSlug   *string
	Timestamp time.Time
}

// RecentActivity returns a goal's recent activity (UNION across milestones,
// tasks via project, and contents via project), newest first.
func (s *Store) RecentActivity(ctx context.Context, goalID uuid.UUID, limit int32) ([]ActivityItem, error) {
	rows, err := s.q.GoalRecentActivity(ctx, db.GoalRecentActivityParams{
		GoalID:     goalID,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying goal recent activity %s: %w", goalID, err)
	}
	result := make([]ActivityItem, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		if r.Ts == nil {
			continue
		}
		result = append(result, ActivityItem{
			Type:      ActivityType(r.ActivityType),
			Title:     r.Title,
			RefID:     r.RefID,
			RefSlug:   r.RefSlug,
			Timestamp: *r.Ts,
		})
	}
	return result, nil
}

func rowToMilestone(r *db.CreateMilestoneRow) *Milestone {
	return &Milestone{
		ID:             r.ID,
		GoalID:         r.GoalID,
		Title:          r.Title,
		Description:    r.Description,
		TargetDeadline: r.TargetDeadline,
		CompletedAt:    r.CompletedAt,
		Position:       r.Position,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
	}
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
