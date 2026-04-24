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

// SearchItems searches todo items with optional filters.
func (s *Store) SearchItems(ctx context.Context, query, projectSlug, stateFilter *string, completedAfter, completedBefore *time.Time, maxResults int32) ([]SearchDetail, error) {
	var escapedQuery *string
	if query != nil {
		v := escapeILIKE(*query)
		escapedQuery = &v
	}
	rows, err := s.q.SearchTodoItems(ctx, db.SearchTodoItemsParams{
		Query:           escapedQuery,
		ProjectSlug:     projectSlug,
		StateFilter:     stateFilter,
		CompletedAfter:  completedAfter,
		CompletedBefore: completedBefore,
		MaxResults:      maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("searching todo items: %w", err)
	}
	items := make([]SearchDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		items[i] = SearchDetail{
			ID:            r.ID,
			Title:         r.Title,
			State:         State(r.State),
			Due:           r.Due,
			ProjectTitle:  r.ProjectTitle,
			ProjectSlug:   r.ProjectSlug,
			Energy:        r.Energy,
			Priority:      r.Priority,
			RecurInterval: r.RecurInterval,
			RecurUnit:     r.RecurUnit,
			CompletedAt:   r.CompletedAt,
			Description:   r.Description,
			CreatedAt:     r.CreatedAt,
			UpdatedAt:     r.UpdatedAt,
		}
	}
	return items, nil
}

// CompletedItemsDetailSince returns todo items completed since the given time.
func (s *Store) CompletedItemsDetailSince(ctx context.Context, since time.Time) ([]CompletedDetail, error) {
	rows, err := s.q.CompletedTodoDetailSince(ctx, &since)
	if err != nil {
		return nil, fmt.Errorf("listing completed todo items since %s: %w", since.Format(time.DateOnly), err)
	}
	result := make([]CompletedDetail, len(rows))
	for i, r := range rows {
		result[i] = CompletedDetail{
			ID:           r.ID,
			Title:        r.Title,
			CompletedAt:  r.CompletedAt,
			ProjectTitle: r.ProjectTitle,
		}
	}
	return result, nil
}

// ItemsCreatedSince returns todo items created since the given time.
func (s *Store) ItemsCreatedSince(ctx context.Context, since time.Time) ([]CreatedDetail, error) {
	rows, err := s.q.TodoItemsCreatedSince(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("listing todo items created since %s: %w", since.Format(time.DateOnly), err)
	}
	result := make([]CreatedDetail, len(rows))
	for i, r := range rows {
		result[i] = CreatedDetail{
			ID:           r.ID,
			Title:        r.Title,
			CreatedAt:    r.CreatedAt,
			ProjectTitle: r.ProjectTitle,
		}
	}
	return result, nil
}
