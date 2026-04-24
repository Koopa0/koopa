package content

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/db"
)

// Search performs full-text search on published content.
func (s *Store) Search(ctx context.Context, query string, contentType *Type, page, perPage int) ([]Content, int, error) {
	ct := nullContentType(contentType)

	rows, err := s.q.SearchContents(ctx, db.SearchContentsParams{
		WebsearchToTsquery: query,
		Limit:              int32(perPage),              // #nosec G115 -- pagination values are bounded by API layer
		Offset:             int32((page - 1) * perPage), // #nosec G115 -- pagination values are bounded by API layer
		ContentType:        ct,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("searching contents: %w", err)
	}

	count, err := s.q.SearchContentsCount(ctx, db.SearchContentsCountParams{
		WebsearchToTsquery: query,
		ContentType:        ct,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("counting search results: %w", err)
	}

	contents := make([]Content, len(rows))
	ids := make([]uuid.UUID, len(rows))
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
		ids[i] = r.ID
	}

	tagMap, err := s.tagsForContents(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	for i := range contents {
		contents[i].Tags = tagMap[contents[i].ID]
	}

	return contents, int(count), nil
}

// InternalSearch performs full-text search on published content without visibility filter.
// Used by MCP tools that need access to all content including private.
func (s *Store) InternalSearch(ctx context.Context, query string, page, perPage int) ([]Content, int, error) {
	rows, err := s.q.InternalSearchContents(ctx, db.InternalSearchContentsParams{
		WebsearchToTsquery: query,
		Limit:              int32(perPage),              // #nosec G115 -- pagination values are bounded by API layer
		Offset:             int32((page - 1) * perPage), // #nosec G115 -- pagination values are bounded by API layer
	})
	if err != nil {
		return nil, 0, fmt.Errorf("internal searching contents: %w", err)
	}

	count, err := s.q.InternalSearchContentsCount(ctx, query)
	if err != nil {
		return nil, 0, fmt.Errorf("counting internal search results: %w", err)
	}

	contents := make([]Content, len(rows))
	ids := make([]uuid.UUID, len(rows))
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
		ids[i] = r.ID
	}

	tagMap, err := s.tagsForContents(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	for i := range contents {
		contents[i].Tags = tagMap[contents[i].ID]
	}

	return contents, int(count), nil
}
