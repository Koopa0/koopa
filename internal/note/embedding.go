// Copyright 2026 Koopa. All rights reserved.

// embedding.go owns the embedding write path — the reconciler-facing
// store methods that list rows missing embeddings and persist derived
// vectors. The read side (SemanticSearch) lives in store.go next to the
// FTS Search it pairs with.

package note

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/pgvector/pgvector-go"

	"github.com/Koopa0/koopa/internal/db"
	"github.com/Koopa0/koopa/internal/embedder"
)

var _ embedder.Source = (*Store)(nil)

// MissingEmbeddings returns up to limit notes whose embedding is NULL,
// oldest first. No maturity filter — archived notes stay searchable, so
// they get embeddings too.
func (s *Store) MissingEmbeddings(ctx context.Context, limit int) ([]embedder.Document, error) {
	rows, err := s.q.NotesMissingEmbedding(ctx, int32(limit)) // #nosec G115 -- limit is a small reconciler batch size
	if err != nil {
		return nil, fmt.Errorf("listing notes missing embeddings: %w", err)
	}
	docs := make([]embedder.Document, len(rows))
	for i, r := range rows {
		docs[i] = embedder.Document{ID: r.ID, Title: r.Title, Body: r.Body}
	}
	return docs, nil
}

// SetEmbedding persists the derived embedding for one note. updated_at is
// left untouched and no activity_events row is written — an embedding
// write is derived data, not an edit.
func (s *Store) SetEmbedding(ctx context.Context, id uuid.UUID, embedding pgvector.Vector) error {
	if err := s.q.SetNoteEmbedding(ctx, db.SetNoteEmbeddingParams{
		ID:        id,
		Embedding: &embedding,
	}); err != nil {
		return fmt.Errorf("setting embedding on note %s: %w", id, err)
	}
	return nil
}
