package note

import (
	"context"
	"fmt"

	"github.com/Koopa0/koopa/internal/search"
)

// SearchSource adapts note.Store.Search into a search.Source. Notes are
// Zettelkasten-private, so this source only appears in admin search —
// there is no public counterpart.
type SearchSource struct {
	store *Store
}

// NewSearchSource returns a search.Source backed by the given note Store.
func NewSearchSource(store *Store) *SearchSource {
	return &SearchSource{store: store}
}

// Kind identifies hits from this source.
func (SearchSource) Kind() search.Kind { return search.KindNote }

// Search runs note.Store.Search (FTS over title+body) and converts
// rows into search.Result. Body is not projected into the excerpt to
// keep the result slim; the editor route fetches the full body.
func (s *SearchSource) Search(ctx context.Context, query string, limit int) ([]search.Result, error) {
	if limit <= 0 {
		return []search.Result{}, nil
	}
	rows, err := s.store.Search(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("note search: %w", err)
	}
	out := make([]search.Result, len(rows))
	for i := range rows {
		out[i] = search.Result{
			Type:  search.KindNote,
			ID:    rows[i].ID,
			Slug:  rows[i].Slug,
			Title: rows[i].Title,
		}
	}
	return out, nil
}
