// Copyright 2026 Koopa. All rights reserved.

// embedding.go owns the embedding write path — the reconciler-facing
// store methods that list rows missing embeddings and persist derived
// vectors. Read-side embedding math (similarity queries, the knowledge
// graph) lives in graph.go.

package content

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/pgvector/pgvector-go"

	"github.com/Koopa0/koopa/internal/db"
	"github.com/Koopa0/koopa/internal/embedder"
)

var _ embedder.Source = (*Store)(nil)

// MissingEmbeddings returns up to limit non-archived contents whose
// embedding is NULL, oldest first. Archived content is excluded — it is
// unreachable from every search path, so embedding it would waste API
// quota.
func (s *Store) MissingEmbeddings(ctx context.Context, limit int) ([]embedder.Document, error) {
	rows, err := s.q.ContentsMissingEmbedding(ctx, int32(limit)) // #nosec G115 -- limit is a small reconciler batch size
	if err != nil {
		return nil, fmt.Errorf("listing contents missing embeddings: %w", err)
	}
	docs := make([]embedder.Document, len(rows))
	for i, r := range rows {
		docs[i] = embedder.Document{ID: r.ID, Title: r.Title, Body: r.Body}
	}
	return docs, nil
}

// SetEmbedding persists the derived embedding for one content row.
// updated_at is left untouched and no activity_events row is written —
// an embedding write is derived data, not an edit.
func (s *Store) SetEmbedding(ctx context.Context, id uuid.UUID, embedding pgvector.Vector) error {
	if err := s.q.SetContentEmbedding(ctx, db.SetContentEmbeddingParams{
		ID:        id,
		Embedding: &embedding,
	}); err != nil {
		return fmt.Errorf("setting embedding on content %s: %w", id, err)
	}
	return nil
}
