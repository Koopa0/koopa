// Copyright 2026 Koopa. All rights reserved.

// store.go holds every Store method for the goal package — goals,
// milestones, and the cross-table RecentActivity UNION. Kept in one
// file because Milestone and ActivityItem are read-only siblings of
// Goal with no independent lifecycle worth splitting out.

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

// mapWriteError classifies a PostgreSQL goal/milestone-write failure into a
// feature sentinel. A unique violation (23505) becomes ErrConflict; a
// foreign-key violation (23503 — a goal's area_id or a milestone's goal_id
// pointing at a non-existent row) or a CHECK violation (23514 — a blank
// title via chk_goal_title_not_blank / chk_milestone_title_not_blank) becomes
// ErrInvalidInput; any other error is wrapped with the supplied context.
func mapWriteError(err error, operation string) error {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
		return fmt.Errorf("%s: %w", operation, err)
	}
	switch pgErr.Code {
	case pgerrcode.UniqueViolation:
		return ErrConflict
	case pgerrcode.ForeignKeyViolation, pgerrcode.CheckViolation:
		return ErrInvalidInput
	default:
		return fmt.Errorf("%s: %w", operation, err)
	}
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
		return nil, mapWriteError(err, "creating milestone")
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

// GoalsByArea returns the non-proposed goals filed under an area, with
// milestone counts and area name resolved. Row shape and ordering match
// GoalsByOptionalStatus, so it maps to the same ActiveGoalSummary. Returns an
// empty slice (never nil) when the area has no goals.
func (s *Store) GoalsByArea(ctx context.Context, areaID uuid.UUID) ([]ActiveGoalSummary, error) {
	rows, err := s.q.GoalsByArea(ctx, &areaID)
	if err != nil {
		return nil, fmt.Errorf("querying goals for area %s: %w", areaID, err)
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
		return nil, mapWriteError(err, "creating goal")
	}
	g := rowToGoal(&r)
	return &g, nil
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
		CreatedBy:   r.CreatedBy,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// Area is a PARA classification row consumed by the admin area selector.
type Area struct {
	ID        uuid.UUID `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	SortOrder int32     `json:"sort_order"`
}

// Areas returns every PARA area ordered by sort_order then name.
func (s *Store) Areas(ctx context.Context) ([]Area, error) {
	rows, err := s.q.Areas(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing areas: %w", err)
	}
	areas := make([]Area, len(rows))
	for i := range rows {
		r := &rows[i]
		areas[i] = Area{
			ID:        r.ID,
			Slug:      r.Slug,
			Name:      r.Name,
			SortOrder: r.SortOrder,
		}
	}
	return areas, nil
}

// AreaDetail is a single PARA area's full row, backing the admin area-detail
// page header.
type AreaDetail struct {
	ID          uuid.UUID `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	SortOrder   int32     `json:"sort_order"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AreaByID returns a single PARA area by id. Returns ErrNotFound when no area
// matches.
func (s *Store) AreaByID(ctx context.Context, id uuid.UUID) (*AreaDetail, error) {
	r, err := s.q.AreaDetailByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying area %s: %w", id, err)
	}
	return &AreaDetail{
		ID:          r.ID,
		Slug:        r.Slug,
		Name:        r.Name,
		Description: r.Description,
		Status:      r.Status,
		SortOrder:   r.SortOrder,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}, nil
}

// CreatedArea is the active PARA area returned by CreateArea — the owner's
// direct-create counterpart to ProposedArea. created_by is NULL (owner-made),
// so the field is omitted from JSON.
type CreatedArea struct {
	ID          uuid.UUID `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	SortOrder   int32     `json:"sort_order"`
	CreatedBy   *string   `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateAreaParams holds the fields for the owner's direct area create. Slug
// is derived + validated by the caller (handler) against chk_area_slug_format.
type CreateAreaParams struct {
	Slug        string
	Name        string
	Description string
}

// CreateArea inserts an active PARA area (status='active', created_by=NULL) —
// the owner's direct-create path, distinct from the agent ProposeArea draft.
// Error mapping via mapProposeError: a 23505 on the unique slug becomes
// ErrConflict; a CHECK violation (23514 — blank name, malformed slug) becomes
// ErrInvalidInput. The 23503 (FK) branch mapProposeError also covers is dead on
// this path — the INSERT writes no FK column (created_by is NULL, no area_id).
func (s *Store) CreateArea(ctx context.Context, p *CreateAreaParams) (*CreatedArea, error) {
	r, err := s.q.CreateArea(ctx, db.CreateAreaParams{
		Slug:        p.Slug,
		Name:        p.Name,
		Description: p.Description,
	})
	if err != nil {
		return nil, mapProposeError(err, "creating area")
	}
	return &CreatedArea{
		ID:          r.ID,
		Slug:        r.Slug,
		Name:        r.Name,
		Description: r.Description,
		Status:      r.Status,
		SortOrder:   r.SortOrder,
		CreatedBy:   r.CreatedBy,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}, nil
}

// UpdateParams holds optional fields for updating a goal. nil means
// "leave unchanged".
type UpdateParams struct {
	ID          uuid.UUID
	Title       *string
	Description *string
	Quarter     *string
	Deadline    *time.Time
	AreaID      *uuid.UUID
}

// Update applies a partial update to a goal's shaping fields. Status is
// not touched — it transitions through UpdateStatus.
func (s *Store) Update(ctx context.Context, p *UpdateParams) (*Goal, error) {
	r, err := s.q.UpdateGoal(ctx, db.UpdateGoalParams{
		ID:             p.ID,
		NewTitle:       p.Title,
		NewDescription: p.Description,
		NewQuarter:     p.Quarter,
		NewDeadline:    p.Deadline,
		NewAreaID:      p.AreaID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapWriteError(err, fmt.Sprintf("updating goal %s", p.ID))
	}
	g := rowToGoal(&r)
	return &g, nil
}

// UpdateMilestoneParams holds optional fields for updating a milestone.
// nil means "leave unchanged". GoalID binds the update to the parent
// goal — a mismatch surfaces as ErrNotFound.
type UpdateMilestoneParams struct {
	ID             uuid.UUID
	GoalID         uuid.UUID
	Title          *string
	Description    *string
	TargetDeadline *time.Time
}

// UpdateMilestone applies a partial update to a milestone owned by the
// given goal. Returns ErrNotFound when the milestone does not exist or
// belongs to a different goal.
func (s *Store) UpdateMilestone(ctx context.Context, p *UpdateMilestoneParams) (*Milestone, error) {
	r, err := s.q.UpdateMilestone(ctx, db.UpdateMilestoneParams{
		ID:                p.ID,
		GoalID:            p.GoalID,
		NewTitle:          p.Title,
		NewDescription:    p.Description,
		NewTargetDeadline: p.TargetDeadline,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating milestone %s: %w", p.ID, err)
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

// DeleteMilestone deletes a milestone owned by the given goal. Returns
// ErrNotFound when the milestone does not exist or belongs to a
// different goal. Completed milestones are deletable; position gaps in
// the remaining siblings are left as-is.
func (s *Store) DeleteMilestone(ctx context.Context, goalID, id uuid.UUID) error {
	n, err := s.q.DeleteMilestone(ctx, db.DeleteMilestoneParams{ID: id, GoalID: goalID})
	if err != nil {
		return fmt.Errorf("deleting milestone %s: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AreaIDBySlugOrName resolves an ACTIVE area slug or case-insensitive name to
// a UUID. Returns ErrNotFound if no active area matches — a proposed area is
// an inert draft and is not resolvable here, so it cannot become a goal's
// parent until the owner activates it.
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

// AreaIDBySlugOrNameIncludingProposed resolves an area slug or
// case-insensitive name to a UUID, matching proposed areas as well as active
// ones. Returns ErrNotFound if no area matches. Used ONLY by propose_goal so a
// goal can be proposed under an area that is proposed but not yet activated
// (the proposal bundle); every other caller uses the active-only resolver.
func (s *Store) AreaIDBySlugOrNameIncludingProposed(ctx context.Context, identifier string) (uuid.UUID, error) {
	id, err := s.q.AreaIDBySlugOrNameIncludingProposed(ctx, identifier)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNotFound
		}
		return uuid.Nil, fmt.Errorf("resolving area %q (incl. proposed): %w", identifier, err)
	}
	return id, nil
}

// ProposedArea is the inert-draft area returned by ProposeArea / ActivateArea.
type ProposedArea struct {
	ID        uuid.UUID `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedBy *string   `json:"created_by,omitempty"`
}

// ProposeAreaParams holds the fields for an agent-proposed area draft. Slug is
// derived by the caller (handler) and must satisfy chk_area_slug_format.
// Rationale is the agent's optional why-now justification; nil when omitted,
// stored as NULL.
type ProposeAreaParams struct {
	Slug        string
	Name        string
	Description string
	CreatedBy   string
	Rationale   *string
}

// ProposeArea inserts an agent-proposed area as an inert draft
// (status='proposed'). A 23505 on the unique slug becomes ErrConflict; a
// CHECK violation (blank name, malformed slug) becomes ErrInvalidInput.
func (s *Store) ProposeArea(ctx context.Context, p *ProposeAreaParams) (*ProposedArea, error) {
	r, err := s.q.ProposeArea(ctx, db.ProposeAreaParams{
		Slug:              p.Slug,
		Name:              p.Name,
		Description:       p.Description,
		CreatedBy:         &p.CreatedBy,
		ProposalRationale: p.Rationale,
	})
	if err != nil {
		return nil, mapProposeError(err, "proposing area")
	}
	return &ProposedArea{
		ID:        r.ID,
		Slug:      r.Slug,
		Name:      r.Name,
		Status:    r.Status,
		CreatedBy: r.CreatedBy,
	}, nil
}

// ProposeGoalParams holds the fields for an agent-proposed goal draft.
// AreaID is resolved by the caller (existing-active or just-proposed area);
// Milestones are appended in insertion order under the new goal. Rationale is
// the agent's optional why-now justification; nil when omitted, stored as NULL.
type ProposeGoalParams struct {
	Title       string
	Description string
	AreaID      *uuid.UUID
	CreatedBy   string
	Rationale   *string
	Milestones  []string
}

// ProposeGoal inserts an agent-proposed goal as an inert draft
// (status='proposed') plus its milestones, all within the supplied
// transaction so a mid-loop failure rolls the whole proposal back. Bind the
// store to the tx with WithTx before calling. A bad area_id FK (23503) becomes
// ErrInvalidInput; a CHECK violation (blank title) likewise.
func (s *Store) ProposeGoal(ctx context.Context, p *ProposeGoalParams) (*Goal, error) {
	r, err := s.q.ProposeGoal(ctx, db.ProposeGoalParams{
		Title:             p.Title,
		Description:       p.Description,
		AreaID:            p.AreaID,
		CreatedBy:         &p.CreatedBy,
		ProposalRationale: p.Rationale,
	})
	if err != nil {
		return nil, mapProposeError(err, "proposing goal")
	}
	g := rowToGoal(&r)

	for i, title := range p.Milestones {
		if _, err := s.q.CreateMilestoneWithPosition(ctx, db.CreateMilestoneWithPositionParams{
			GoalID:   g.ID,
			Title:    title,
			Position: int32(i),
		}); err != nil {
			return nil, mapProposeError(err, "proposing goal milestone")
		}
	}
	return &g, nil
}

// mapProposeError classifies a proposal-write failure. A unique violation
// (23505 — duplicate area slug) becomes ErrConflict; a foreign-key (23503 —
// bad area_id) or CHECK violation (23514 — blank title/name, malformed slug)
// becomes ErrInvalidInput; anything else is wrapped with context.
func mapProposeError(err error, operation string) error {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
		return fmt.Errorf("%s: %w", operation, err)
	}
	switch pgErr.Code {
	case pgerrcode.UniqueViolation:
		return ErrConflict
	case pgerrcode.ForeignKeyViolation, pgerrcode.CheckViolation:
		return ErrInvalidInput
	default:
		return fmt.Errorf("%s: %w", operation, err)
	}
}

// ActivateGoal transitions a proposed goal to not_started. Proposed-only:
// ErrNotFound when the goal is missing, ErrNotProposed when it exists but is
// not proposed (the zero-rows case is disambiguated with a follow-up read).
func (s *Store) ActivateGoal(ctx context.Context, id uuid.UUID) (*Goal, error) {
	r, err := s.q.ActivateGoal(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, s.classifyProposedGoalMiss(ctx, id)
		}
		return nil, fmt.Errorf("activating goal %s: %w", id, err)
	}
	g := rowToGoal(&r)
	return &g, nil
}

// ActivateArea transitions a proposed area to active. Proposed-only, same
// missing/not-proposed disambiguation as ActivateGoal.
func (s *Store) ActivateArea(ctx context.Context, id uuid.UUID) (*ProposedArea, error) {
	r, err := s.q.ActivateArea(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, s.classifyProposedAreaMiss(ctx, id)
		}
		return nil, fmt.Errorf("activating area %s: %w", id, err)
	}
	return &ProposedArea{
		ID:        r.ID,
		Slug:      r.Slug,
		Name:      r.Name,
		Status:    r.Status,
		CreatedBy: r.CreatedBy,
	}, nil
}

// RejectGoal hard-deletes a proposed goal (milestones CASCADE). Proposed-only:
// ErrNotFound when missing, ErrNotProposed when the row exists but is not
// proposed — a real goal is never deleted by this path.
func (s *Store) RejectGoal(ctx context.Context, id uuid.UUID) error {
	n, err := s.q.DeleteProposedGoal(ctx, id)
	if err != nil {
		return fmt.Errorf("rejecting goal %s: %w", id, err)
	}
	if n > 0 {
		return nil
	}
	return s.classifyProposedGoalMiss(ctx, id)
}

// RejectArea hard-deletes a proposed area AND, in the same transaction, every
// proposed goal under it — a proposal is one indivisible theme+goals bundle.
// Active goals under the area survive (their area_id is SET NULL by the FK).
// Bind the store to a tx with WithTx before calling so both deletes are
// atomic. Proposed-only: ErrNotFound when missing, ErrNotProposed otherwise.
func (s *Store) RejectArea(ctx context.Context, id uuid.UUID) error {
	if _, err := s.q.DeleteProposedGoalsByArea(ctx, &id); err != nil {
		return fmt.Errorf("rejecting proposed goals under area %s: %w", id, err)
	}
	n, err := s.q.DeleteProposedArea(ctx, id)
	if err != nil {
		return fmt.Errorf("rejecting area %s: %w", id, err)
	}
	if n > 0 {
		return nil
	}
	return s.classifyProposedAreaMiss(ctx, id)
}

// ProposalsPending is the nav-badge breakdown of items awaiting owner triage.
type ProposalsPending struct {
	Goals int64 `json:"proposed_goals"`
	Areas int64 `json:"proposed_areas"`
}

// ProposalsPendingCount returns the count of proposed goals and proposed areas
// awaiting owner triage.
func (s *Store) ProposalsPendingCount(ctx context.Context) (ProposalsPending, error) {
	r, err := s.q.ProposalsPendingCount(ctx)
	if err != nil {
		return ProposalsPending{}, fmt.Errorf("counting pending proposals: %w", err)
	}
	return ProposalsPending{Goals: r.ProposedGoals, Areas: r.ProposedAreas}, nil
}

// ProposedGoalSummary is a proposed goal row for the triage surface, with area
// name and milestone count resolved. ProposalRationale is the agent's why-now
// justification (nil when none was given) — surfaced only here in triage, never
// in the active-goal list or brief.
type ProposedGoalSummary struct {
	ID                uuid.UUID  `json:"id"`
	Title             string     `json:"title"`
	Description       string     `json:"description"`
	AreaID            *uuid.UUID `json:"area_id,omitempty"`
	AreaName          string     `json:"area_name"`
	CreatedBy         *string    `json:"created_by,omitempty"`
	ProposalRationale *string    `json:"proposal_rationale,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	MilestoneTotal    int64      `json:"milestone_total"`
}

// ProposedAreaSummary is a proposed area row for the triage surface.
// ProposalRationale is the agent's why-now justification (nil when none was
// given) — surfaced only here in triage.
type ProposedAreaSummary struct {
	ID                uuid.UUID `json:"id"`
	Slug              string    `json:"slug"`
	Name              string    `json:"name"`
	Description       string    `json:"description"`
	CreatedBy         *string   `json:"created_by,omitempty"`
	ProposalRationale *string   `json:"proposal_rationale,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

// ProposedGoals returns every proposed goal awaiting triage, newest first.
func (s *Store) ProposedGoals(ctx context.Context) ([]ProposedGoalSummary, error) {
	rows, err := s.q.ProposedGoals(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing proposed goals: %w", err)
	}
	out := make([]ProposedGoalSummary, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = ProposedGoalSummary{
			ID:                r.ID,
			Title:             r.Title,
			Description:       r.Description,
			AreaID:            r.AreaID,
			AreaName:          r.AreaName,
			CreatedBy:         r.CreatedBy,
			ProposalRationale: r.ProposalRationale,
			CreatedAt:         r.CreatedAt,
			MilestoneTotal:    r.MilestoneTotal,
		}
	}
	return out, nil
}

// ProposedAreas returns every proposed area awaiting triage, newest first.
func (s *Store) ProposedAreas(ctx context.Context) ([]ProposedAreaSummary, error) {
	rows, err := s.q.ProposedAreas(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing proposed areas: %w", err)
	}
	out := make([]ProposedAreaSummary, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = ProposedAreaSummary{
			ID:                r.ID,
			Slug:              r.Slug,
			Name:              r.Name,
			Description:       r.Description,
			CreatedBy:         r.CreatedBy,
			ProposalRationale: r.ProposalRationale,
			CreatedAt:         r.CreatedAt,
		}
	}
	return out, nil
}

// classifyProposedGoalMiss disambiguates a zero-rows proposed-goal mutation:
// the row is missing (ErrNotFound) or exists but is not proposed
// (ErrNotProposed).
func (s *Store) classifyProposedGoalMiss(ctx context.Context, id uuid.UUID) error {
	if _, err := s.q.GoalByID(ctx, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("classifying proposed-goal miss %s: %w", id, err)
	}
	return ErrNotProposed
}

// classifyProposedAreaMiss is the area counterpart of classifyProposedGoalMiss.
func (s *Store) classifyProposedAreaMiss(ctx context.Context, id uuid.UUID) error {
	if _, err := s.q.AreaByID(ctx, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("classifying proposed-area miss %s: %w", id, err)
	}
	return ErrNotProposed
}
