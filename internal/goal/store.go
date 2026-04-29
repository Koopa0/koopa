// store.go holds every Store method for the goal package — goals,
// milestones, and the cross-table RecentActivity UNION. Kept in one
// file because Milestone and ActivityItem are read-only siblings of
// Goal with no independent lifecycle worth splitting out.
//
// Naming quirks worth knowing before adding callers:
//   - Create(ctx, *CreateParams) is the idiomatic constructor.
//     CreateGoal(ctx, title, description, status, areaID, quarter,
//     deadline) is a legacy 7-arg signature kept for existing callers.
//     New code should use Create + CreateParams.
//   - ByID(ctx, id) returns *GoalWithArea (joins area name).
//     GoalByID(ctx, id) returns bare *Goal. Pick the one matching what
//     you need — don't pay for the join if the area name is unused.

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

	"github.com/Koopa0/koopa/internal/db"
)

// Store handles database operations for goals.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a Store bound to tx for all queries. Used by callers
// composing multi-store transactions — typically via api.ActorMiddleware
// (HTTP) or mcp.Server.withActorTx (MCP). The tx carries koopa.actor
// so audit triggers attribute mutations correctly.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
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

// ActiveGoals returns in_progress goals with milestone counts.
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

// GoalsByOptionalStatus returns goals filtered by optional status, with milestone counts.
// Pass nil for all statuses.
func (s *Store) GoalsByOptionalStatus(ctx context.Context, status *string) ([]ActiveGoalSummary, error) {
	rows, err := s.q.GoalsByOptionalStatus(ctx, status)
	if err != nil {
		return nil, fmt.Errorf("querying goals by status: %w", err)
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

// Create inserts a new goal with status=not_started.
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
	ActivityTodoCompleted      ActivityType = "todo_completed"
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
		ID:          r.ID,
		Title:       r.Title,
		Description: r.Description,
		Status:      Status(r.Status),
		AreaID:      r.AreaID,
		Quarter:     r.Quarter,
		Deadline:    r.Deadline,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// AreaIDBySlugOrName resolves an area slug or case-insensitive name to a
// UUID. Returns ErrNotFound if no area matches. Used by propose_goal /
// propose_project when the caller passes an area identifier instead of
// a UUID.
func (s *Store) AreaIDBySlugOrName(ctx context.Context, identifier string) (uuid.UUID, error) {
	id, err := s.q.AreaIDBySlugOrName(ctx, identifier)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNotFound
		}
		return uuid.Nil, fmt.Errorf("resolving area %q: %w", identifier, err)
	}
	return id, nil
}
