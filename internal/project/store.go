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

	"github.com/Koopa0/koopa0.dev/internal/db"
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

// CreateProject inserts a new project.
func (s *Store) CreateProject(ctx context.Context, p *CreateParams) (*Project, error) {
	if p.TechStack == nil {
		p.TechStack = []string{}
	}
	if p.Highlights == nil {
		p.Highlights = []string{}
	}
	r, err := s.q.CreateProject(ctx, db.CreateProjectParams{
		Slug:            p.Slug,
		Title:           p.Title,
		Description:     p.Description,
		LongDescription: p.LongDescription,
		Role:            p.Role,
		TechStack:       p.TechStack,
		Highlights:      p.Highlights,
		Problem:         p.Problem,
		Solution:        p.Solution,
		Architecture:    p.Architecture,
		Results:         p.Results,
		GithubUrl:       p.GithubURL,
		LiveUrl:         p.LiveURL,
		Featured:        p.Featured,
		IsPublic:        p.IsPublic,
		SortOrder:       int32(p.SortOrder), // #nosec G115 -- sort order is a small UI ordering value, not user-controlled
		Status:          db.ProjectStatus(p.Status),
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
	var sortOrder *int32
	if p.SortOrder != nil {
		v := int32(*p.SortOrder) // #nosec G115 -- sort order is a small UI ordering value, not user-controlled
		sortOrder = &v
	}
	r, err := s.q.UpdateProject(ctx, db.UpdateProjectParams{
		ID:              id,
		Slug:            p.Slug,
		Title:           p.Title,
		Description:     p.Description,
		LongDescription: p.LongDescription,
		Role:            p.Role,
		TechStack:       p.TechStack,
		Highlights:      p.Highlights,
		Problem:         p.Problem,
		Solution:        p.Solution,
		Architecture:    p.Architecture,
		Results:         p.Results,
		GithubUrl:       p.GithubURL,
		LiveUrl:         p.LiveURL,
		Featured:        p.Featured,
		IsPublic:        p.IsPublic,
		SortOrder:       sortOrder,
		Status:          nullProjectStatus(p.Status),
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

// ActiveProjects returns projects with in-progress or maintained status.
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

// UpdateStatus updates a project's status and optionally its description and expected cadence.
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
	p := rowToProject(&r)
	return &p, nil
}

func rowToProject(r *db.Project) Project {
	return Project{
		ID:              r.ID,
		Slug:            r.Slug,
		Title:           r.Title,
		Description:     r.Description,
		LongDescription: r.LongDescription,
		Role:            r.Role,
		TechStack:       r.TechStack,
		Highlights:      r.Highlights,
		Problem:         r.Problem,
		Solution:        r.Solution,
		Architecture:    r.Architecture,
		Results:         r.Results,
		GithubURL:       r.GithubUrl,
		LiveURL:         r.LiveUrl,
		Featured:        r.Featured,
		IsPublic:        r.IsPublic,
		SortOrder:       int(r.SortOrder),
		Status:          Status(r.Status),
		NotionPageID:    r.NotionPageID,
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
