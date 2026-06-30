// Copyright 2026 Koopa. All rights reserved.

// history.go owns read-only reporting queries over the historical
// record of todos — completed-since, created-since, full-text search.
// Split from todo.go so the core lifecycle surface stays focused and
// reporting queries have a clear home.

package todo

import (
	"context"
	"fmt"
	"time"

	"github.com/Koopa0/koopa/internal/db"
)

// SearchResolvedItems searches resolved ("已了結") todos — done, dropped
// (archived/dismissed), or a recurring routine's recent occurrence — by title
// or description, for the Complete tab's ?q= path. It shares the resolution
// arms of ResolvedItemsDetailSince so the search covers the same set the default
// view shows, not just done items. See SearchResolvedTodoItems in query.sql.
func (s *Store) SearchResolvedItems(ctx context.Context, query string, since time.Time, maxResults int32) ([]ResolvedDetail, error) {
	escaped := escapeILIKE(query)
	rows, err := s.q.SearchResolvedTodoItems(ctx, db.SearchResolvedTodoItemsParams{
		Query:      &escaped,
		Since:      &since,
		MaxResults: maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("searching resolved todo items: %w", err)
	}
	result := make([]ResolvedDetail, len(rows))
	for i := range rows {
		resolvedAt := rows[i].ResolvedAt
		result[i] = ResolvedDetail{
			ID:           rows[i].ID,
			Title:        rows[i].Title,
			State:        State(rows[i].State),
			CompletedAt:  &resolvedAt,
			ProjectTitle: rows[i].ProjectTitle,
		}
	}
	return result, nil
}

// ResolvedItemsDetailSince returns todos resolved ("已了結") since the given
// time — done, dropped (archived/dismissed), or a recurring routine's recent
// occurrence — for the Complete tab. See ResolvedTodoDetailSince in query.sql.
func (s *Store) ResolvedItemsDetailSince(ctx context.Context, since time.Time) ([]ResolvedDetail, error) {
	rows, err := s.q.ResolvedTodoDetailSince(ctx, &since)
	if err != nil {
		return nil, fmt.Errorf("listing resolved todo items since %s: %w", since.Format(time.DateOnly), err)
	}
	result := make([]ResolvedDetail, len(rows))
	for i := range rows {
		resolvedAt := rows[i].ResolvedAt
		result[i] = ResolvedDetail{
			ID:           rows[i].ID,
			Title:        rows[i].Title,
			State:        State(rows[i].State),
			CompletedAt:  &resolvedAt,
			ProjectTitle: rows[i].ProjectTitle,
		}
	}
	return result, nil
}
