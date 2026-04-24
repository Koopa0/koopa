package content

import (
	"context"
	"fmt"

	"github.com/Koopa0/koopa/internal/search"
)

// SearchSource adapts content.Store.InternalSearch into a search.Source
// so the admin global search endpoint can fold content hits into the
// unified result stream. Score is left at zero — InternalSearch does
// not project the FTS rank today; when it does, wire it here.
type SearchSource struct {
	store *Store
}

// NewSearchSource returns a search.Source backed by the given content Store.
func NewSearchSource(store *Store) *SearchSource {
	return &SearchSource{store: store}
}

// Kind identifies hits from this source.
func (SearchSource) Kind() search.Kind { return search.KindContent }

// Search runs InternalSearch over the contents table and converts the
// rows into search.Result. Returns an empty slice on zero hits so the
// handler's merge step has no nil case to guard.
func (s *SearchSource) Search(ctx context.Context, query string, limit int) ([]search.Result, error) {
	if limit <= 0 {
		return []search.Result{}, nil
	}
	rows, _, err := s.store.InternalSearch(ctx, query, 1, limit)
	if err != nil {
		return nil, fmt.Errorf("content search: %w", err)
	}
	out := make([]search.Result, len(rows))
	for i := range rows {
		out[i] = search.Result{
			Type:    search.KindContent,
			ID:      rows[i].ID,
			Slug:    rows[i].Slug,
			Title:   rows[i].Title,
			Excerpt: rows[i].Excerpt,
		}
	}
	return out, nil
}
