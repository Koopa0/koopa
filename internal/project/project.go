// Package project provides project planning and public portfolio profiles.
//
// File map:
//   - project.go (this file) — types + core Store methods for the
//     projects table (CRUD, status transitions, identity lookups by
//     id/slug/alias/title/repo, list-by-goal summaries).
//   - profile.go              — Store methods for project_profiles
//     (the public portfolio facet, 1:1 with projects).
//   - handler.go              — HTTP handlers, including the Detail
//     aggregator that fans out to todo/activity/content stores.
//
// project.go mixes types and Store deliberately: the wire-contract
// shapes (Project, Profile, Detail, PublicListing, ActivityItem,
// ContentSummary) are all populated against this package's Store
// methods, so splitting into a types-only file would fragment the
// cohesion. profile.go IS split because the profile methods own a
// separate primary key and their own transactional contract.
//
// Load-bearing invariant: UpdateStatus detects transitions into
// 'archived' and demotes the matching profile in the SAME tx. This
// replaces the former archive_project_profile trigger — per the
// trigger policy in .claude/rules/database.md, cross-aggregate side
// effects belong in Go. Do NOT move this back into a trigger.
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

// Project is the PARA planning aggregate. Public portfolio/case-study fields
// live on Profile (1:1). A project may exist without a profile; a profile
// without its project is impossible (project_id is the profile's primary key).
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

// Profile is the public portfolio facet of a project. 1:1 with Project.
type Profile struct {
	ProjectID       uuid.UUID `json:"project_id"`
	LongDescription *string   `json:"long_description,omitempty"`
	Role            *string   `json:"role,omitempty"`
	TechStack       []string  `json:"tech_stack"`
	Highlights      []string  `json:"highlights"`
	Problem         *string   `json:"problem,omitempty"`
	Solution        *string   `json:"solution,omitempty"`
	Architecture    *string   `json:"architecture,omitempty"`
	Results         *string   `json:"results,omitempty"`
	GithubURL       *string   `json:"github_url,omitempty"`
	LiveURL         *string   `json:"live_url,omitempty"`
	CoverImage      *string   `json:"cover_image,omitempty"`
	Featured        bool      `json:"featured"`
	IsPublic        bool      `json:"is_public"`
	SortOrder       int       `json:"sort_order"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// UpsertProfileParams holds the parameters for creating or updating a project profile.
// project_id is the primary key; existing profiles are replaced.
type UpsertProfileParams struct {
	ProjectID       uuid.UUID `json:"project_id"`
	LongDescription *string   `json:"long_description,omitempty"`
	Role            *string   `json:"role,omitempty"`
	TechStack       []string  `json:"tech_stack"`
	Highlights      []string  `json:"highlights"`
	Problem         *string   `json:"problem,omitempty"`
	Solution        *string   `json:"solution,omitempty"`
	Architecture    *string   `json:"architecture,omitempty"`
	Results         *string   `json:"results,omitempty"`
	GithubURL       *string   `json:"github_url,omitempty"`
	LiveURL         *string   `json:"live_url,omitempty"`
	CoverImage      *string   `json:"cover_image,omitempty"`
	Featured        bool      `json:"featured"`
	IsPublic        bool      `json:"is_public"`
	SortOrder       int       `json:"sort_order"`
}

// PublicListing combines a Project's planning fields with its Profile's
// public portfolio fields for the portfolio listing endpoint.
type PublicListing struct {
	ID              uuid.UUID  `json:"id"`
	Slug            string     `json:"slug"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	Status          Status     `json:"status"`
	Repo            *string    `json:"repo,omitempty"`
	Deadline        *time.Time `json:"deadline,omitempty"`
	LastActivityAt  *time.Time `json:"last_activity_at,omitempty"`
	LongDescription *string    `json:"long_description,omitempty"`
	Role            *string    `json:"role,omitempty"`
	TechStack       []string   `json:"tech_stack"`
	Highlights      []string   `json:"highlights"`
	Problem         *string    `json:"problem,omitempty"`
	Solution        *string    `json:"solution,omitempty"`
	Architecture    *string    `json:"architecture,omitempty"`
	Results         *string    `json:"results,omitempty"`
	GithubURL       *string    `json:"github_url,omitempty"`
	LiveURL         *string    `json:"live_url,omitempty"`
	CoverImage      *string    `json:"cover_image,omitempty"`
	Featured        bool       `json:"featured"`
	SortOrder       int        `json:"sort_order"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// Detail is the admin project detail aggregate returned by
// GET /api/admin/projects/{id}. Assembled by the handler from the core
// project row, its profile (for problem/solution/architecture), goal
// breadcrumb, grouped tasks, recent activity, and related content. The
// shape matches the frontend ProjectDetail contract so the inspector
// panel renders directly from the wire response.
//
// Area is the project's area id as a string (empty when the project has
// no area). Deriving a human-readable name would require a separate
// lookup that the inspector does not currently need.
type Detail struct {
	ID             uuid.UUID        `json:"id"`
	Title          string           `json:"title"`
	Slug           string           `json:"slug"`
	Description    string           `json:"description"`
	Problem        *string          `json:"problem"`
	Solution       *string          `json:"solution"`
	Architecture   *string          `json:"architecture"`
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
	// ErrNotFound indicates the project or profile does not exist.
	ErrNotFound = errors.New("project: not found")

	// ErrConflict indicates a duplicate slug or primary key conflict.
	ErrConflict = errors.New("project: conflict")
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

// PublicProjects returns only public projects ordered by featured status and sort order.
func (s *Store) PublicProjects(ctx context.Context) ([]Project, error) {
	rows, err := s.q.PublicProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing public projects: %w", err)
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

// ProjectBySlug returns a single project by slug.
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
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating project: %w", err)
	}
	proj := rowToProject(&r)
	return &proj, nil
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
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("updating project %s: %w", id, err)
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

// ActiveProjects returns projects with in_progress or maintained status.
func (s *Store) ActiveProjects(ctx context.Context) ([]Project, error) {
	rows, err := s.q.ActiveProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing active projects: %w", err)
	}
	projects := make([]Project, len(rows))
	for i := range rows {
		projects[i] = rowToProject(&rows[i])
	}
	return projects, nil
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

// ProjectByRepo returns a project by its GitHub repository full name (e.g. "owner/repo").
func (s *Store) ProjectByRepo(ctx context.Context, repo string) (*Project, error) {
	r, err := s.q.ProjectByRepo(ctx, &repo)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying project by repo %s: %w", repo, err)
	}
	p := rowToProject(&r)
	return &p, nil
}

// UpdateStatus updates a project's status and optionally its description
// and expected cadence. When a project transitions into the archived
// state from any other state, the matching project_profile is demoted
// (is_public=false, featured=false). This replaces the former
// archive_project_profile() trigger — per .claude/rules/postgres-patterns.md
// business logic belongs in Go.
//
// CALLER CONTRACT: the status update and the profile demote must commit
// as a unit. Callers that need atomicity (admin HTTP path) MUST pass a
// tx-bound Store via WithTx(tx); ActorMiddleware supplies the tx. On a
// pool-backed Store the two writes run on separate connections and a
// mid-step failure leaves the project status flipped but the profile
// still public — acceptable only for contexts (tests, offline MCP)
// where that divergence is surfaced loudly.
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
		return nil, fmt.Errorf("updating project %s status: %w", id, err)
	}

	// Archive coupling: when the row transitioned into archived, demote
	// the profile. The transition check mirrors the old trigger's
	// WHEN clause (NEW.status = 'archived' AND OLD.status IS DISTINCT
	// FROM NEW.status) so this is a behaviour-preserving move.
	if r.Status == db.ProjectStatusArchived && r.OldStatus != db.ProjectStatusArchived {
		if err := s.q.DemoteProjectProfileOnArchive(ctx, id); err != nil {
			return nil, fmt.Errorf("demoting profile for archived project %s: %w", id, err)
		}
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

// ListByStatus returns projects filtered by status.
// Special values: "active" returns in_progress + maintained, "all" returns everything.
func (s *Store) ListByStatus(ctx context.Context, status string) ([]Project, error) {
	rows, err := s.q.ListByStatus(ctx, status)
	if err != nil {
		return nil, fmt.Errorf("listing projects by status %q: %w", status, err)
	}
	projects := make([]Project, len(rows))
	for i := range rows {
		projects[i] = rowToProject(&rows[i])
	}
	return projects, nil
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
