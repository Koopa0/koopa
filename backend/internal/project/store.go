package project

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/blog-backend/internal/db"
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

// NewStore returns a Store backed by the given pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{q: db.New(pool)}
}

// Projects returns all projects ordered by featured status and sort order.
func (s *Store) Projects(ctx context.Context) ([]Project, error) {
	rows, err := s.q.Projects(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	projects := make([]Project, len(rows))
	for i, r := range rows {
		projects[i] = rowToProject(r)
	}
	return projects, nil
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
	p := rowToProject(r)
	return &p, nil
}

// CreateProject inserts a new project.
func (s *Store) CreateProject(ctx context.Context, p CreateParams) (*Project, error) {
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
		SortOrder:       int32(p.SortOrder), // #nosec G115 -- sort order is a small UI ordering value, not user-controlled
		Status:          db.ProjectStatus(p.Status),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating project: %w", err)
	}
	proj := rowToProject(r)
	return &proj, nil
}

// UpdateProject updates a project.
func (s *Store) UpdateProject(ctx context.Context, id uuid.UUID, p UpdateParams) (*Project, error) {
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
		SortOrder:       sortOrder,
		Status:          nullProjectStatus(p.Status),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("updating project %s: %w", id, err)
	}
	proj := rowToProject(r)
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
	for i, r := range rows {
		projects[i] = rowToProject(r)
	}
	return projects, nil
}

// UpsertByNotionPageID upserts a project by its Notion page ID.
func (s *Store) UpsertByNotionPageID(ctx context.Context, p UpsertByNotionParams) (*Project, error) {
	r, err := s.q.UpsertProjectByNotionPageID(ctx, db.UpsertProjectByNotionPageIDParams{
		Slug:         p.Slug,
		Title:        p.Title,
		Description:  p.Description,
		Status:       db.ProjectStatus(p.Status),
		Area:         p.Area,
		Deadline:     p.Deadline,
		NotionPageID: &p.NotionPageID,
	})
	if err != nil {
		return nil, fmt.Errorf("upserting project by notion page %s: %w", p.NotionPageID, err)
	}
	proj := rowToProject(r)
	return &proj, nil
}

// UpdateLastActivity sets last_activity_at to now for the project identified by Notion page ID.
func (s *Store) UpdateLastActivity(ctx context.Context, notionPageID string) error {
	if err := s.q.UpdateProjectLastActivity(ctx, &notionPageID); err != nil {
		return fmt.Errorf("updating last activity for notion page %s: %w", notionPageID, err)
	}
	return nil
}

func rowToProject(r db.Project) Project {
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
		SortOrder:       int(r.SortOrder),
		Status:          Status(r.Status),
		NotionPageID:    r.NotionPageID,
		Area:            r.Area,
		Deadline:        r.Deadline,
		LastActivityAt:  r.LastActivityAt,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}
