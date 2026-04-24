package project

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/db"
)

// ProfileByProjectID returns a single project profile by project_id.
func (s *Store) ProfileByProjectID(ctx context.Context, projectID uuid.UUID) (*Profile, error) {
	r, err := s.q.ProfileByProjectID(ctx, projectID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying project profile %s: %w", projectID, err)
	}
	prof := rowToProfile(&r)
	return &prof, nil
}

// UpsertProfile creates or replaces a project's portfolio profile.
func (s *Store) UpsertProfile(ctx context.Context, p *UpsertProfileParams) (*Profile, error) {
	if p.TechStack == nil {
		p.TechStack = []string{}
	}
	if p.Highlights == nil {
		p.Highlights = []string{}
	}
	r, err := s.q.UpsertProfile(ctx, db.UpsertProfileParams{
		ProjectID:       p.ProjectID,
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
		CoverImage:      p.CoverImage,
		Featured:        p.Featured,
		IsPublic:        p.IsPublic,
		SortOrder:       int32(p.SortOrder), // #nosec G115 -- bounded by UI
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.ForeignKeyViolation {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("upserting project profile %s: %w", p.ProjectID, err)
	}
	prof := rowToProfile(&r)
	return &prof, nil
}

// DeleteProfile removes a project's portfolio profile while leaving the project intact.
func (s *Store) DeleteProfile(ctx context.Context, projectID uuid.UUID) error {
	if err := s.q.DeleteProfile(ctx, projectID); err != nil {
		return fmt.Errorf("deleting project profile %s: %w", projectID, err)
	}
	return nil
}

// PublicProfiles returns all public profiles joined with their projects,
// ordered for portfolio display.
func (s *Store) PublicProfiles(ctx context.Context) ([]PublicListing, error) {
	rows, err := s.q.PublicProfiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing public profiles: %w", err)
	}
	out := make([]PublicListing, len(rows))
	for i := range rows {
		r := &rows[i]
		tech := r.TechStack
		if tech == nil {
			tech = []string{}
		}
		hi := r.Highlights
		if hi == nil {
			hi = []string{}
		}
		out[i] = PublicListing{
			ID:              r.ID,
			Slug:            r.Slug,
			Title:           r.Title,
			Description:     r.Description,
			Status:          Status(r.Status),
			Repo:            r.Repo,
			Deadline:        r.Deadline,
			LastActivityAt:  r.LastActivityAt,
			LongDescription: r.LongDescription,
			Role:            r.Role,
			TechStack:       tech,
			Highlights:      hi,
			Problem:         r.Problem,
			Solution:        r.Solution,
			Architecture:    r.Architecture,
			Results:         r.Results,
			GithubURL:       r.GithubUrl,
			LiveURL:         r.LiveUrl,
			CoverImage:      r.CoverImage,
			Featured:        r.Featured,
			SortOrder:       int(r.SortOrder),
			UpdatedAt:       r.UpdatedAt,
		}
	}
	return out, nil
}

func rowToProfile(r *db.ProjectProfile) Profile {
	tech := r.TechStack
	if tech == nil {
		tech = []string{}
	}
	hi := r.Highlights
	if hi == nil {
		hi = []string{}
	}
	return Profile{
		ProjectID:       r.ProjectID,
		LongDescription: r.LongDescription,
		Role:            r.Role,
		TechStack:       tech,
		Highlights:      hi,
		Problem:         r.Problem,
		Solution:        r.Solution,
		Architecture:    r.Architecture,
		Results:         r.Results,
		GithubURL:       r.GithubUrl,
		LiveURL:         r.LiveUrl,
		CoverImage:      r.CoverImage,
		Featured:        r.Featured,
		IsPublic:        r.IsPublic,
		SortOrder:       int(r.SortOrder),
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}
