// Copyright 2026 Koopa. All rights reserved.

// embedding.go owns the embedding write path for the reading corpus — the
// reconciler-facing sources that list shelf rows and diary entries missing an
// embedding and persist the derived vectors. The shelf and its diary are two
// separate embedder sources (two tables, two NULL-embedding columns), each a
// small adapter over the package Store. Read-side search (the FTS + semantic
// corpus queries) lives in search.go.

package reading

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/pgvector/pgvector-go"

	"github.com/Koopa0/koopa/internal/db"
	"github.com/Koopa0/koopa/internal/embedder"
)

var (
	_ embedder.Source = (*ShelfEmbeddingSource)(nil)
	_ embedder.Source = (*ReflectionEmbeddingSource)(nil)
)

// ShelfEmbeddingSource embeds the readings shelf rows. The embed text is the
// book title plus author (embedder.Document{Title, Body}); the reconciler's
// embedText joins them.
type ShelfEmbeddingSource struct {
	store *Store
}

// NewShelfEmbeddingSource returns the reconciler source for the readings shelf.
func NewShelfEmbeddingSource(store *Store) *ShelfEmbeddingSource {
	return &ShelfEmbeddingSource{store: store}
}

// MissingEmbeddings returns up to limit shelf rows whose embedding is NULL,
// oldest first. Title carries the book title, Body the author — embedText
// joins them into the embedding input.
func (s *ShelfEmbeddingSource) MissingEmbeddings(ctx context.Context, limit int) ([]embedder.Document, error) {
	rows, err := s.store.q.ReadingsMissingEmbedding(ctx, int32(limit)) // #nosec G115 -- limit is a small reconciler batch size
	if err != nil {
		return nil, fmt.Errorf("listing readings missing embeddings: %w", err)
	}
	docs := make([]embedder.Document, len(rows))
	for i, r := range rows {
		docs[i] = embedder.Document{ID: r.ID, Title: r.Title, Body: r.Author}
	}
	return docs, nil
}

// SetEmbedding persists the derived embedding for one shelf row. updated_at is
// left untouched — an embedding write is derived data, not an edit.
func (s *ShelfEmbeddingSource) SetEmbedding(ctx context.Context, id uuid.UUID, embedding pgvector.Vector) error {
	if err := s.store.q.SetReadingEmbedding(ctx, db.SetReadingEmbeddingParams{
		ID:        id,
		Embedding: &embedding,
	}); err != nil {
		return fmt.Errorf("setting embedding on reading %s: %w", id, err)
	}
	return nil
}

// ReflectionEmbeddingSource embeds the reading_reflections diary rows. The
// embed text is the reflection body alone: Title carries the body and Body is
// empty, so embedText returns the body verbatim.
type ReflectionEmbeddingSource struct {
	store *Store
}

// NewReflectionEmbeddingSource returns the reconciler source for the reading
// diary.
func NewReflectionEmbeddingSource(store *Store) *ReflectionEmbeddingSource {
	return &ReflectionEmbeddingSource{store: store}
}

// MissingEmbeddings returns up to limit diary rows whose embedding is NULL,
// oldest first. The body is placed in Document.Title (with an empty Body) so
// embedText embeds the body alone — reflections have no title field.
func (s *ReflectionEmbeddingSource) MissingEmbeddings(ctx context.Context, limit int) ([]embedder.Document, error) {
	rows, err := s.store.q.ReadingReflectionsMissingEmbedding(ctx, int32(limit)) // #nosec G115 -- limit is a small reconciler batch size
	if err != nil {
		return nil, fmt.Errorf("listing reading reflections missing embeddings: %w", err)
	}
	docs := make([]embedder.Document, len(rows))
	for i, r := range rows {
		docs[i] = embedder.Document{ID: r.ID, Title: r.Body}
	}
	return docs, nil
}

// SetEmbedding persists the derived embedding for one diary row.
func (s *ReflectionEmbeddingSource) SetEmbedding(ctx context.Context, id uuid.UUID, embedding pgvector.Vector) error {
	if err := s.store.q.SetReadingReflectionEmbedding(ctx, db.SetReadingReflectionEmbeddingParams{
		ID:        id,
		Embedding: &embedding,
	}); err != nil {
		return fmt.Errorf("setting embedding on reading reflection %s: %w", id, err)
	}
	return nil
}
