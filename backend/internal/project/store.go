package project

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

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
	for i, r := range rows {
		projects[i] = rowToProject(r)
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
		Public:          p.Public,
		SortOrder:       int32(p.SortOrder), // #nosec G115 -- sort order is a small UI ordering value, not user-controlled
		Status:          db.ProjectStatus(p.Status),
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
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
		Public:          p.Public,
		SortOrder:       sortOrder,
		Status:          nullProjectStatus(p.Status),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
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

// ProjectByAlias resolves a project alias to a project via the project_aliases table.
func (s *Store) ProjectByAlias(ctx context.Context, alias string) (*Project, error) {
	r, err := s.q.ProjectByAlias(ctx, alias)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying project by alias %s: %w", alias, err)
	}
	p := rowToProject(r)
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
	p := rowToProject(r)
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
	p := rowToProject(r)
	return &p, nil
}

// UpsertByNotionPageID upserts a project by its Notion page ID.
// If the generated slug conflicts with an existing project, a numeric
// suffix is appended (e.g. "-2", "-3") up to 5 attempts.
func (s *Store) UpsertByNotionPageID(ctx context.Context, p UpsertByNotionParams) (*Project, error) {
	slug := p.Slug
	for i := range 5 {
		r, err := s.q.UpsertProjectByNotionPageID(ctx, db.UpsertProjectByNotionPageIDParams{
			Slug:         slug,
			Title:        p.Title,
			Description:  p.Description,
			Status:       db.ProjectStatus(p.Status),
			Area:         p.Area,
			Deadline:     p.Deadline,
			NotionPageID: &p.NotionPageID,
		})
		if err != nil {
			if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" && pgErr.ConstraintName == "projects_slug_key" {
				// suffix: "title-2", "title-3", … "title-6"
				slug = fmt.Sprintf("%s-%d", p.Slug, i+2)
				continue
			}
			return nil, fmt.Errorf("upserting project by notion page %s: %w", p.NotionPageID, err)
		}
		proj := rowToProject(r)
		return &proj, nil
	}
	return nil, fmt.Errorf("upserting project by notion page %s: slug conflict after retries", p.NotionPageID)
}

// UpdateLastActivity sets last_activity_at to now for the project identified by Notion page ID.
func (s *Store) UpdateLastActivity(ctx context.Context, notionPageID string) error {
	if err := s.q.UpdateProjectLastActivity(ctx, &notionPageID); err != nil {
		return fmt.Errorf("updating last activity for notion page %s: %w", notionPageID, err)
	}
	return nil
}

// NotionPageIDs returns all notion page IDs for projects synced from Notion.
func (s *Store) NotionPageIDs(ctx context.Context) ([]string, error) {
	ptrs, err := s.q.NotionProjectPageIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing project notion page ids: %w", err)
	}
	ids := make([]string, 0, len(ptrs))
	for _, p := range ptrs {
		if p != nil {
			ids = append(ids, *p)
		}
	}
	return ids, nil
}

// ArchiveByNotionPageID marks a single project as archived by its Notion page ID.
// Used when a Notion page is trashed. Returns rows affected (0 if not found or already archived).
func (s *Store) ArchiveByNotionPageID(ctx context.Context, notionPageID string) (int64, error) {
	n, err := s.q.ArchiveProjectByNotionPageID(ctx, &notionPageID)
	if err != nil {
		return 0, fmt.Errorf("archiving project by notion page %s: %w", notionPageID, err)
	}
	return n, nil
}

// ArchiveOrphanNotion marks projects as archived if their notion_page_id
// is not in the given list of active IDs. Returns the number of archived projects.
// Returns 0 immediately if activeIDs is empty to avoid archiving all records.
func (s *Store) ArchiveOrphanNotion(ctx context.Context, activeIDs []string) (int64, error) {
	if len(activeIDs) == 0 {
		return 0, nil
	}
	n, err := s.q.ArchiveOrphanNotionProjects(ctx, activeIDs)
	if err != nil {
		return 0, fmt.Errorf("archiving orphan notion projects: %w", err)
	}
	return n, nil
}

// SlugByNotionPageID returns the slug of a project identified by its Notion page ID.
func (s *Store) SlugByNotionPageID(ctx context.Context, notionPageID string) (string, error) {
	slug, err := s.q.ProjectSlugByNotionPageID(ctx, &notionPageID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("querying project slug by notion page id %s: %w", notionPageID, err)
	}
	return slug, nil
}

// IDByNotionPageID returns the UUID of a project identified by its Notion page ID.
func (s *Store) IDByNotionPageID(ctx context.Context, notionPageID string) (uuid.UUID, error) {
	id, err := s.q.ProjectIDByNotionPageID(ctx, &notionPageID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.UUID{}, ErrNotFound
		}
		return uuid.UUID{}, fmt.Errorf("querying project id by notion page id %s: %w", notionPageID, err)
	}
	return id, nil
}

// ActiveSlugsWithRepo returns slugs of active projects that have a linked
// repository and activity since the given time.
func (s *Store) ActiveSlugsWithRepo(ctx context.Context, since time.Time) ([]string, error) {
	slugs, err := s.q.ActiveProjectSlugsWithRepo(ctx, &since)
	if err != nil {
		return nil, fmt.Errorf("listing active project slugs with repo: %w", err)
	}
	return slugs, nil
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
	p := rowToProject(r)
	return &p, nil
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
		Public:          r.Public,
		SortOrder:       int(r.SortOrder),
		Status:          Status(r.Status),
		NotionPageID:    r.NotionPageID,
		Repo:            r.Repo,
		Area:            r.Area,
		Deadline:        r.Deadline,
		LastActivityAt:  r.LastActivityAt,
		ExpectedCadence: r.ExpectedCadence,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}
