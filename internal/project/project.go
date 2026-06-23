// Copyright 2026 Koopa. All rights reserved.

// Package project provides PARA project planning.
//
// File map:
//   - project.go (this file) — types + core Store methods for the
//     projects table (CRUD, status transitions, identity lookups by
//     id/slug/alias/title/repo, list-by-goal summaries).
//   - handler.go              — HTTP handlers, including the Detail
//     aggregator that fans out to todo/activity/content stores.
//
// project.go mixes types and Store deliberately: the wire-contract
// shapes (Project, Detail, ActivityItem, ContentSummary) are all
// populated against this package's Store methods, so splitting into a
// types-only file would fragment the cohesion.
package project

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

// Status represents a project's lifecycle status.
type Status string

const (
	// StatusProposed indicates an agent-proposed inert draft awaiting owner
	// triage. A proposed project is excluded from the admin project list and
	// the goal project view; the owner activates it
	// (→ in_progress) or rejects it (hard DELETE) in admin. Slug/alias/title/id
	// resolvers still match it so capture_inbox can link a todo before activation.
	StatusProposed Status = "proposed"

	// StatusPlanned indicates the project is planned but not yet started.
	StatusPlanned Status = "planned"

	// StatusInProgress indicates the project is actively being developed.
	StatusInProgress Status = "in_progress"

	// StatusOnHold indicates the project is paused.
	StatusOnHold Status = "on_hold"

	// StatusCompleted indicates the project is finished.
	StatusCompleted Status = "completed"

	// StatusMaintained indicates the project is in maintenance mode.
	StatusMaintained Status = "maintained"

	// StatusArchived indicates the project is archived and no longer active.
	StatusArchived Status = "archived"
)

// Project is the PARA planning aggregate.
type Project struct {
	ID              uuid.UUID  `json:"id"`
	Slug            string     `json:"slug"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	Status          Status     `json:"status"`
	Repo            *string    `json:"repo,omitempty"`
	AreaID          *uuid.UUID `json:"area_id,omitempty"`
	GoalID          *uuid.UUID `json:"goal_id,omitempty"`
	Deadline        *time.Time `json:"deadline,omitempty"`
	LastActivityAt  *time.Time `json:"last_activity_at,omitempty"`
	ExpectedCadence *string    `json:"expected_cadence,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// CreateParams holds the parameters for creating a project.
//
// GoalID and AreaID are optional links to the parent goal / area. When
// supplied at creation time the project is wired in one INSERT — there
// is no separate Update call needed for the link to land, and
// goal_progress / area listings see the new project on the next read.
// Callers that do not know the parent (scaffolding, admin UI form
// without a selection) pass nil for both.
type CreateParams struct {
	Slug        string     `json:"slug"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Status      Status     `json:"status"`
	GoalID      *uuid.UUID `json:"goal_id,omitempty"`
	AreaID      *uuid.UUID `json:"area_id,omitempty"`
}

// UpdateParams holds the parameters for updating a project.
type UpdateParams struct {
	Slug        *string `json:"slug,omitempty"`
	Title       *string `json:"title,omitempty"`
	Description *string `json:"description,omitempty"`
	Status      *Status `json:"status,omitempty"`
}

// Detail is the admin project detail aggregate returned by
// GET /api/admin/projects/{id}. Assembled by the handler from the core
// project row, goal breadcrumb, grouped tasks, recent activity, and
// related content. The shape matches the frontend ProjectDetail
// contract so the inspector panel renders directly from the wire
// response.
//
// Area is the project's area id as a string (empty when the project has
// no area). Deriving a human-readable name would require a separate
// lookup that the inspector does not currently need.
type Detail struct {
	ID             uuid.UUID        `json:"id"`
	Title          string           `json:"title"`
	Slug           string           `json:"slug"`
	Description    string           `json:"description"`
	Status         Status           `json:"status"`
	Area           string           `json:"area"`
	GoalBreadcrumb *GoalBreadcrumb  `json:"goal_breadcrumb"`
	TodosByState   any              `json:"todos_by_state"` // shape provided by caller; keeps this package dependency-free
	RecentActivity []ActivityItem   `json:"recent_activity"`
	RelatedContent []ContentSummary `json:"related_content"`
}

// GoalBreadcrumb is the minimal goal reference used by the inspector
// header. Nil when the project has no goal.
type GoalBreadcrumb struct {
	GoalID    uuid.UUID `json:"goal_id"`
	GoalTitle string    `json:"goal_title"`
}

// ActivityItem is the activity projection consumed by the inspector.
// Source fields (entity_type, vcs kind) are flattened into Type so the
// frontend renders a single timeline without caring which table the row
// came from.
type ActivityItem struct {
	Type      string    `json:"type"`
	Title     string    `json:"title"`
	Timestamp time.Time `json:"timestamp"`
}

// ContentSummary is the content projection consumed by the inspector's
// related content list. The backend content package owns the full
// shape; this is a copy to keep project free of a direct content import.
type ContentSummary struct {
	ID    uuid.UUID `json:"id"`
	Title string    `json:"title"`
	Slug  string    `json:"slug"`
	Type  string    `json:"type"`
}

var (
	// ErrNotFound indicates the project does not exist.
	ErrNotFound = errors.New("project: not found")

	// ErrConflict indicates a duplicate slug or primary key conflict.
	ErrConflict = errors.New("project: conflict")

	// ErrInvalidInput signals a client-supplied value the database rejected:
	// a foreign key pointing at a non-existent area_id / goal_id, or a check
	// violation (chk_project_slug_format, the expected_cadence CHECK).
	ErrInvalidInput = errors.New("project: invalid input")

	// ErrNotProposed indicates an activate/reject targeted a project that
	// exists but is not in status=proposed. Real planning rows are not
	// activated or hard-deleted through the proposal-triage path.
	ErrNotProposed = errors.New("project: not proposed")
)

// nullProjectStatus converts a *Status to db.NullProjectStatus.
func nullProjectStatus(s *Status) db.NullProjectStatus {
	if s == nil {
		return db.NullProjectStatus{}
	}
	return db.NullProjectStatus{ProjectStatus: db.ProjectStatus(*s), Valid: true}
}

// Store handles database operations for projects.
type Store struct {
	dbtx db.DBTX
	q    *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{dbtx: dbtx, q: db.New(dbtx)}
}

// WithTx returns a Store bound to tx for all queries. Used by callers
// composing multi-store transactions — typically via api.ActorMiddleware
// (HTTP) or mcp.Server.withActorTx (MCP). The tx carries koopa.actor
// so audit triggers attribute mutations correctly.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{dbtx: tx, q: s.q.WithTx(tx)}
}

// Projects returns all projects ordered by featured status and sort order.
func (s *Store) Projects(ctx context.Context) ([]Project, error) {
	rows, err := s.q.Projects(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	projects := make([]Project, len(rows))
	for i := range rows {
		projects[i] = rowToProject(&rows[i])
	}
	return projects, nil
}

// ProjectByID returns a single project by UUID.
func (s *Store) ProjectByID(ctx context.Context, id uuid.UUID) (*Project, error) {
	r, err := s.q.ProjectByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying project %s: %w", id, err)
	}
	p := rowToProject(&r)
	return &p, nil
}

// DetailRow bundles a Project with its goal breadcrumb title. GoalTitle
// is nil when the project has no goal (GoalID nil) or when the referenced
// goal was deleted. The goals table has no slug, so the breadcrumb is
// title-only — matching the GoalBreadcrumb wire shape.
type DetailRow struct {
	Project
	GoalTitle *string
}

// ProjectDetailByID returns the project plus its goal breadcrumb in a
// single LEFT JOIN query. Used by the admin detail endpoint in place of
// ProjectByID + a separate goal-title lookup — resolving the former
// project→goal dependency at the SQL layer where no import cycle exists.
func (s *Store) ProjectDetailByID(ctx context.Context, id uuid.UUID) (*DetailRow, error) {
	r, err := s.q.ProjectDetailByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying project detail %s: %w", id, err)
	}
	return &DetailRow{
		Project: Project{
			ID:              r.ID,
			Slug:            r.Slug,
			Title:           r.Title,
			Description:     r.Description,
			Status:          Status(r.Status),
			Repo:            r.Repo,
			AreaID:          r.AreaID,
			GoalID:          r.GoalID,
			Deadline:        r.Deadline,
			LastActivityAt:  r.LastActivityAt,
			ExpectedCadence: r.ExpectedCadence,
			CreatedAt:       r.CreatedAt,
			UpdatedAt:       r.UpdatedAt,
		},
		GoalTitle: r.GoalTitle,
	}, nil
}

// ProjectBySlug returns a single project by slug, regardless of status.
func (s *Store) ProjectBySlug(ctx context.Context, slug string) (*Project, error) {
	r, err := s.q.ProjectBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying project %s: %w", slug, err)
	}
	p := rowToProject(&r)
	return &p, nil
}

// CreateProject inserts a new project. GoalID and AreaID may be nil,
// in which case the project lands without parent links.
func (s *Store) CreateProject(ctx context.Context, p *CreateParams) (*Project, error) {
	r, err := s.q.CreateProject(ctx, db.CreateProjectParams{
		Slug:        p.Slug,
		Title:       p.Title,
		Description: p.Description,
		Status:      db.ProjectStatus(p.Status),
		GoalID:      p.GoalID,
		AreaID:      p.AreaID,
	})
	if err != nil {
		return nil, mapWriteError(err, "creating project")
	}
	proj := rowToProject(&r)
	return &proj, nil
}

// mapWriteError classifies a PostgreSQL project-write failure into a feature
// sentinel. A unique violation (23505) on the slug becomes ErrConflict; a
// foreign-key (23503 — area_id / goal_id pointing at a non-existent row) or
// check-constraint (23514 — chk_project_slug_format, the expected_cadence
// CHECK) violation becomes ErrInvalidInput; any other error is wrapped with
// the supplied context.
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

// ProposeProjectParams holds the fields for an agent-proposed project draft.
// Slug is derived by the caller (handler) and must satisfy
// chk_project_slug_format. Rationale is the agent's optional why-now
// justification; nil when omitted, stored as NULL.
type ProposeProjectParams struct {
	Slug        string
	Title       string
	Description string
	CreatedBy   string
	Rationale   *string
}

// ProposeProject inserts an agent-proposed project as an inert draft
// (status='proposed'). A unique violation on the slug (23505) becomes
// ErrConflict; a CHECK violation (blank title, malformed slug) or a bad
// created_by FK (23503) becomes ErrInvalidInput.
func (s *Store) ProposeProject(ctx context.Context, p *ProposeProjectParams) (*Project, error) {
	r, err := s.q.ProposeProject(ctx, db.ProposeProjectParams{
		Slug:              p.Slug,
		Title:             p.Title,
		Description:       p.Description,
		CreatedBy:         &p.CreatedBy,
		ProposalRationale: p.Rationale,
	})
	if err != nil {
		return nil, mapWriteError(err, "proposing project")
	}
	proj := rowToProject(&r)
	return &proj, nil
}

// ProposedProjectSummary is a proposed project row for the triage surface.
// ProposalRationale is the agent's why-now justification (nil when none was
// given) — surfaced only here in triage, never in the active project list.
type ProposedProjectSummary struct {
	ID                uuid.UUID `json:"id"`
	Slug              string    `json:"slug"`
	Title             string    `json:"title"`
	Description       string    `json:"description"`
	CreatedBy         *string   `json:"created_by,omitempty"`
	ProposalRationale *string   `json:"proposal_rationale,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

// ActivateProject transitions a proposed project to in_progress. Proposed-only:
// ErrNotFound when the project is missing, ErrNotProposed when it exists but is
// not proposed (the zero-rows case is disambiguated with a follow-up read).
func (s *Store) ActivateProject(ctx context.Context, id uuid.UUID) (*Project, error) {
	r, err := s.q.ActivateProject(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, s.classifyProposedProjectMiss(ctx, id)
		}
		return nil, fmt.Errorf("activating project %s: %w", id, err)
	}
	proj := rowToProject(&r)
	return &proj, nil
}

// RejectProject hard-deletes a proposed project. Proposed-only: ErrNotFound when
// missing, ErrNotProposed when the row exists but is not proposed — a real
// project is never deleted by this path. Linked todos and contents survive
// unclassified (their project_id is SET NULL by the FK).
func (s *Store) RejectProject(ctx context.Context, id uuid.UUID) error {
	n, err := s.q.DeleteProposedProject(ctx, id)
	if err != nil {
		return fmt.Errorf("rejecting project %s: %w", id, err)
	}
	if n > 0 {
		return nil
	}
	return s.classifyProposedProjectMiss(ctx, id)
}

// ProposedProjects returns every proposed project awaiting triage, newest first.
func (s *Store) ProposedProjects(ctx context.Context) ([]ProposedProjectSummary, error) {
	rows, err := s.q.ProposedProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing proposed projects: %w", err)
	}
	out := make([]ProposedProjectSummary, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = ProposedProjectSummary{
			ID:                r.ID,
			Slug:              r.Slug,
			Title:             r.Title,
			Description:       r.Description,
			CreatedBy:         r.CreatedBy,
			ProposalRationale: r.ProposalRationale,
			CreatedAt:         r.CreatedAt,
		}
	}
	return out, nil
}

// ProposedProjectsCount returns the number of proposed projects awaiting triage.
func (s *Store) ProposedProjectsCount(ctx context.Context) (int64, error) {
	n, err := s.q.ProposedProjectsCount(ctx)
	if err != nil {
		return 0, fmt.Errorf("counting proposed projects: %w", err)
	}
	return n, nil
}

// classifyProposedProjectMiss disambiguates a zero-rows proposed-project
// mutation: the row is missing (ErrNotFound) or exists but is not proposed
// (ErrNotProposed).
func (s *Store) classifyProposedProjectMiss(ctx context.Context, id uuid.UUID) error {
	if _, err := s.q.ProjectByID(ctx, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("classifying proposed-project miss %s: %w", id, err)
	}
	return ErrNotProposed
}

// UpdateProject updates a project.
func (s *Store) UpdateProject(ctx context.Context, id uuid.UUID, p *UpdateParams) (*Project, error) {
	r, err := s.q.UpdateProject(ctx, db.UpdateProjectParams{
		ID:          id,
		Slug:        p.Slug,
		Title:       p.Title,
		Description: p.Description,
		Status:      nullProjectStatus(p.Status),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapWriteError(err, fmt.Sprintf("updating project %s", id))
	}
	proj := rowToProject(&r)
	return &proj, nil
}

// DeleteProject deletes a project by ID.
func (s *Store) DeleteProject(ctx context.Context, id uuid.UUID) error {
	err := s.q.DeleteProject(ctx, id)
	if err != nil {
		return fmt.Errorf("deleting project %s: %w", id, err)
	}
	return nil
}

// ProjectByAlias resolves a project alias to a project via the project_aliases table.
func (s *Store) ProjectByAlias(ctx context.Context, alias string) (*Project, error) {
	r, err := s.q.ProjectByAlias(ctx, alias)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying project by alias %s: %w", alias, err)
	}
	p := rowToProject(&r)
	return &p, nil
}

// ProjectByTitle returns a single project by case-insensitive title match.
func (s *Store) ProjectByTitle(ctx context.Context, title string) (*Project, error) {
	r, err := s.q.ProjectByTitle(ctx, title)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying project by title %s: %w", title, err)
	}
	p := rowToProject(&r)
	return &p, nil
}

// UpdateStatus updates a project's status and optionally its description
// and expected cadence. Any status transition is a single UPDATE and runs
// on any store.
func (s *Store) UpdateStatus(ctx context.Context, id uuid.UUID, status Status, description, expectedCadence *string) (*Project, error) {
	r, err := s.q.UpdateProjectStatus(ctx, db.UpdateProjectStatusParams{
		ID:              id,
		Status:          db.ProjectStatus(status),
		Description:     description,
		ExpectedCadence: expectedCadence,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapWriteError(err, fmt.Sprintf("updating project %s status", id))
	}

	p := Project{
		ID:              r.ID,
		Slug:            r.Slug,
		Title:           r.Title,
		Description:     r.Description,
		Status:          Status(r.Status),
		Repo:            r.Repo,
		AreaID:          r.AreaID,
		GoalID:          r.GoalID,
		Deadline:        r.Deadline,
		LastActivityAt:  r.LastActivityAt,
		ExpectedCadence: r.ExpectedCadence,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
	return &p, nil
}

func rowToProject(r *db.Project) Project {
	return Project{
		ID:              r.ID,
		Slug:            r.Slug,
		Title:           r.Title,
		Description:     r.Description,
		Status:          Status(r.Status),
		Repo:            r.Repo,
		AreaID:          r.AreaID,
		GoalID:          r.GoalID,
		Deadline:        r.Deadline,
		LastActivityAt:  r.LastActivityAt,
		ExpectedCadence: r.ExpectedCadence,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}

// ProjectSummary is a lightweight project view for goal_progress output.
type ProjectSummary struct {
	ID             uuid.UUID  `json:"id"`
	Slug           string     `json:"slug"`
	Title          string     `json:"title"`
	Status         Status     `json:"status"`
	GoalID         *uuid.UUID `json:"goal_id,omitempty"`
	LastActivityAt *time.Time `json:"last_activity_at,omitempty"`
}

// SummariesByGoalIDs returns lightweight project info for a set of goal IDs.
func (s *Store) SummariesByGoalIDs(ctx context.Context, goalIDs []uuid.UUID) ([]ProjectSummary, error) {
	if len(goalIDs) == 0 {
		return nil, nil
	}
	rows, err := s.q.ProjectSummariesByGoalIDs(ctx, goalIDs)
	if err != nil {
		return nil, fmt.Errorf("querying project summaries by goal IDs: %w", err)
	}
	result := make([]ProjectSummary, len(rows))
	for i := range rows {
		result[i] = ProjectSummary{
			ID:             rows[i].ID,
			Slug:           rows[i].Slug,
			Title:          rows[i].Title,
			Status:         Status(rows[i].Status),
			GoalID:         rows[i].GoalID,
			LastActivityAt: rows[i].LastActivityAt,
		}
	}
	return result, nil
}

// ProjectsByArea returns the active (non-proposed, non-archived) projects filed
// under an area as lightweight summaries, mirroring SummariesByGoalIDs. Returns
// an empty slice (never nil) when the area has no projects.
func (s *Store) ProjectsByArea(ctx context.Context, areaID uuid.UUID) ([]ProjectSummary, error) {
	rows, err := s.q.ProjectsByArea(ctx, &areaID)
	if err != nil {
		return nil, fmt.Errorf("querying projects by area %s: %w", areaID, err)
	}
	result := make([]ProjectSummary, len(rows))
	for i := range rows {
		result[i] = ProjectSummary{
			ID:             rows[i].ID,
			Slug:           rows[i].Slug,
			Title:          rows[i].Title,
			Status:         Status(rows[i].Status),
			GoalID:         rows[i].GoalID,
			LastActivityAt: rows[i].LastActivityAt,
		}
	}
	return result, nil
}
