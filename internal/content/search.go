// Copyright 2026 Koopa. All rights reserved.

package content

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/db"
)

// SearchFilter narrows internal search to a content type and/or created-date
// window. A nil field means "no filter on that dimension". The filter is pushed
// into the SQL WHERE so it applies BEFORE the retrieval limit — a content_type
// filter must not lose recall to a top-N page full of other types.
type SearchFilter struct {
	ContentType *Type
	// CreatedAfter keeps rows created at or after this instant (inclusive).
	CreatedAfter *time.Time
	// CreatedBefore keeps rows created strictly before this instant. Callers
	// wanting a whole-day-inclusive upper bound pass the start of the day AFTER
	// the requested date.
	CreatedBefore *time.Time
}

// InternalSearch performs full-text search on non-archived content for the
// authenticated admin search, optionally narrowed by filter.
func (s *Store) InternalSearch(ctx context.Context, query string, page, perPage int, filter SearchFilter) ([]Content, error) {
	rows, err := s.q.InternalSearchContents(ctx, db.InternalSearchContentsParams{
		WebsearchToTsquery: query,
		Limit:              int32(perPage),              // #nosec G115 -- pagination values are bounded by API layer
		Offset:             int32((page - 1) * perPage), // #nosec G115 -- pagination values are bounded by API layer
		ContentType:        nullContentType(filter.ContentType),
		CreatedAfter:       filter.CreatedAfter,
		CreatedBefore:      filter.CreatedBefore,
	})
	if err != nil {
		return nil, fmt.Errorf("internal searching contents: %w", err)
	}

	contents := make([]Content, len(rows))
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		r := &rows[i]
		contents[i] = rowToContent(contentRow{
			ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
			Type: r.Type, Status: r.Status,
			SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
			IsPublic: r.IsPublic, ProjectID: r.ProjectID,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
			PublishedAt: r.PublishedAt,
			CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
		ids[i] = r.ID
	}

	if err := s.attachBatchTopics(ctx, contents, ids); err != nil {
		return nil, err
	}

	return contents, nil
}
