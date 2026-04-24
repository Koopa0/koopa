// publish.go owns the publication-related store methods: state-based
// reads (ByStatus, PublishedForRSS, AllPublishedSlugs) and the
// PublishContent mutation that promotes a draft to published. The
// mutation is co-located with its read neighbours because the handler
// calls the reads immediately before and after the transition.

package content

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa/internal/db"
)

// ByStatus returns contents filtered by status, limited to limit results.
func (s *Store) ByStatus(ctx context.Context, status string, limit int) ([]Content, error) {
	rows, err := s.q.ContentsByStatus(ctx, db.ContentsByStatusParams{
		Status:     db.ContentStatus(status),
		MaxResults: int32(limit), // #nosec G115 -- bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("listing contents by status %q: %w", status, err)
	}
	contents := make([]Content, len(rows))
	for i := range rows {
		r := &rows[i]
		contents[i] = rowToContent(contentRow{
			ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
			Type: r.Type, Status: r.Status,
			SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
			IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
			PublishedAt: r.PublishedAt,
			CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
	}
	return contents, nil
}

// PublishedForRSS returns recent published content for RSS feed.
func (s *Store) PublishedForRSS(ctx context.Context, limit int) ([]Content, error) {
	rows, err := s.q.PublishedForRSS(ctx, int32(limit)) // #nosec G115 -- RSS limit is a small constant, not user-controlled
	if err != nil {
		return nil, fmt.Errorf("listing contents for rss: %w", err)
	}
	contents := make([]Content, len(rows))
	for i, r := range rows {
		contents[i] = Content{
			ID:          r.ID,
			Slug:        r.Slug,
			Title:       r.Title,
			Excerpt:     r.Excerpt,
			Type:        Type(r.Type),
			PublishedAt: r.PublishedAt,
			UpdatedAt:   r.UpdatedAt,
		}
	}
	return contents, nil
}

// AllPublishedSlugs returns all published content slugs for sitemap.
func (s *Store) AllPublishedSlugs(ctx context.Context) ([]Content, error) {
	rows, err := s.q.AllPublishedSlugs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing slugs for sitemap: %w", err)
	}
	contents := make([]Content, len(rows))
	for i, r := range rows {
		contents[i] = Content{
			Slug:      r.Slug,
			Type:      Type(r.Type),
			UpdatedAt: r.UpdatedAt,
		}
	}
	return contents, nil
}

// PublishContent sets content status to published.
func (s *Store) PublishContent(ctx context.Context, id uuid.UUID) (*Content, error) {
	r, err := s.q.PublishContent(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("publishing content %s: %w", id, err)
	}

	c := rowToContent(contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		PublishedAt: r.PublishedAt,
		CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})

	topics, err := s.TopicsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Topics = topics

	tags, err := s.TagsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Tags = tags

	return &c, nil
}

// SubmitContentForReview transitions a draft content to review atomically.
// Returns ErrInvalidState if the content exists but is not in draft,
// ErrNotFound if the id does not exist at all. The conditional UPDATE is
// race-safe; the extra existence lookup only runs on the rejection path
// to distinguish "wrong status" from "no such row" for correct HTTP mapping.
func (s *Store) SubmitContentForReview(ctx context.Context, id uuid.UUID) (*Content, error) {
	r, err := s.q.SubmitContentForReview(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, s.transitionRejectionReason(ctx, id)
		}
		return nil, fmt.Errorf("submitting content %s for review: %w", id, err)
	}
	return s.hydrateContentRow(ctx, r.ID, &contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		PublishedAt: r.PublishedAt,
		CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

// RevertContentToDraft transitions a review content back to draft atomically.
// Returns ErrInvalidState if the content exists but is not in review,
// ErrNotFound if the id does not exist. Same race-safety rationale as
// SubmitContentForReview.
func (s *Store) RevertContentToDraft(ctx context.Context, id uuid.UUID) (*Content, error) {
	r, err := s.q.RevertContentToDraft(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, s.transitionRejectionReason(ctx, id)
		}
		return nil, fmt.Errorf("reverting content %s to draft: %w", id, err)
	}
	return s.hydrateContentRow(ctx, r.ID, &contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		PublishedAt: r.PublishedAt,
		CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

// ArchiveContentReturning archives content and returns the updated row. The
// :exec variant ArchiveContent is reserved for DeleteContent's soft-delete
// path which discards the row.
func (s *Store) ArchiveContentReturning(ctx context.Context, id uuid.UUID) (*Content, error) {
	r, err := s.q.ArchiveContentReturning(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("archiving content %s: %w", id, err)
	}
	return s.hydrateContentRow(ctx, r.ID, &contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		PublishedAt: r.PublishedAt,
		CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

// transitionRejectionReason maps a conditional-UPDATE miss to the right
// sentinel — ErrNotFound when the id does not exist, ErrInvalidState when
// the row exists but its status did not satisfy the transition guard.
func (s *Store) transitionRejectionReason(ctx context.Context, id uuid.UUID) error {
	if _, err := s.q.ContentByID(ctx, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("checking content %s existence: %w", id, err)
	}
	return ErrInvalidState
}

// hydrateContentRow attaches topics and tags to a Content produced by a
// state-transition query. Shared between all transitions that return the
// updated row.
func (s *Store) hydrateContentRow(ctx context.Context, id uuid.UUID, row *contentRow) (*Content, error) {
	c := rowToContent(*row)
	topics, err := s.TopicsForContent(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("hydrating topics for content %s: %w", id, err)
	}
	c.Topics = topics
	tags, err := s.TagsForContent(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("hydrating tags for content %s: %w", id, err)
	}
	c.Tags = tags
	return &c, nil
}
