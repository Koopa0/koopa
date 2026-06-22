// Copyright 2026 Koopa. All rights reserved.

// search.go owns the read-side search surface for the reading corpus — the
// FTS and pgvector-semantic queries the MCP search_knowledge handler folds
// into its hybrid retrieval. Both a shelf-row hit and a diary hit collapse to
// one CorpusHit linked to the parent book; the handler tags every hit
// source_type=reading. The embedding write path lives in embedding.go.

package reading

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pgvector/pgvector-go"

	"github.com/Koopa0/koopa/internal/db"
)

// CorpusHit is one search hit from the reading corpus, already folded under
// its parent book. ReadingID + Title link back to the book (the MCP handler
// resolves it via get_reading); Excerpt is the matched text — the book title
// for a shelf hit, the diary body for a reflection hit. CreatedAt is the
// matched row's creation time, used by the date filter.
type CorpusHit struct {
	ReadingID uuid.UUID
	Title     string
	Excerpt   string
	CreatedAt time.Time
}

// SearchCorpus runs full-text search over the reading shelf and its diary,
// returning up to limit hits ranked by ts_rank across the union. A shelf hit
// and a reflection hit both fold under the parent book. The slice is never
// nil so the caller's merge step has no nil case to guard.
func (s *Store) SearchCorpus(ctx context.Context, query string, limit int) ([]CorpusHit, error) {
	rows, err := s.q.SearchReadingCorpus(ctx, db.SearchReadingCorpusParams{
		WebsearchToTsquery: query,
		Limit:              int32(limit), // #nosec G115 -- caller bounds limit via clamp
	})
	if err != nil {
		return nil, fmt.Errorf("searching reading corpus: %w", err)
	}
	out := make([]CorpusHit, len(rows))
	for i := range rows {
		out[i] = CorpusHit{
			ReadingID: rows[i].ReadingID,
			Title:     rows[i].Title,
			Excerpt:   rows[i].Excerpt,
			CreatedAt: rows[i].CreatedAt,
		}
	}
	return out, nil
}

// SemanticSearchCorpus runs pgvector cosine search over the reading shelf and
// its diary, returning up to limit hits ranked by distance across the union.
// Rows without an embedding are skipped (filled lazily by the reconciler).
func (s *Store) SemanticSearchCorpus(ctx context.Context, queryEmbedding pgvector.Vector, limit int) ([]CorpusHit, error) {
	rows, err := s.q.SemanticSearchReadingCorpus(ctx, db.SemanticSearchReadingCorpusParams{
		TargetEmbedding: queryEmbedding,
		MaxResults:      int32(limit), // #nosec G115 -- caller bounds limit via clamp
	})
	if err != nil {
		return nil, fmt.Errorf("semantic searching reading corpus: %w", err)
	}
	out := make([]CorpusHit, len(rows))
	for i := range rows {
		out[i] = CorpusHit{
			ReadingID: rows[i].ReadingID,
			Title:     rows[i].Title,
			Excerpt:   rows[i].Excerpt,
			CreatedAt: rows[i].CreatedAt,
		}
	}
	return out, nil
}
