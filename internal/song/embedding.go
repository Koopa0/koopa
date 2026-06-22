// Copyright 2026 Koopa. All rights reserved.

// embedding.go owns the embedding write path for the song corpus — the
// reconciler-facing sources that list shelf rows and reflection entries
// missing an embedding and persist the derived vectors. The shelf and its
// diary are two separate embedder sources (two tables, two NULL-embedding
// columns), each a small adapter over the package Store. Read-side search (the
// FTS + semantic corpus queries) lives in search.go.

package song

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/pgvector/pgvector-go"

	"github.com/Koopa0/koopa/internal/db"
	"github.com/Koopa0/koopa/internal/embedder"
)

var (
	_ embedder.Source = (*ShelfEmbeddingSource)(nil)
	_ embedder.Source = (*ReflectionEmbeddingSource)(nil)
)

// ShelfEmbeddingSource embeds the songs shelf rows. The embed text is the
// Japanese title plus the album and the owner study fields — the study layer
// is the song's searchable substance, so semantic recall should see it.
type ShelfEmbeddingSource struct {
	store *Store
}

// NewShelfEmbeddingSource returns the reconciler source for the songs shelf.
func NewShelfEmbeddingSource(store *Store) *ShelfEmbeddingSource {
	return &ShelfEmbeddingSource{store: store}
}

// MissingEmbeddings returns up to limit shelf rows whose embedding is NULL,
// oldest first. Title carries the Japanese title; Body concatenates the album
// and the study fields (lyrics / translation / vocabulary) so embedText embeds
// the full study substance, not the title alone.
func (s *ShelfEmbeddingSource) MissingEmbeddings(ctx context.Context, limit int) ([]embedder.Document, error) {
	rows, err := s.store.q.SongsMissingEmbedding(ctx, int32(limit)) // #nosec G115 -- limit is a small reconciler batch size
	if err != nil {
		return nil, fmt.Errorf("listing songs missing embeddings: %w", err)
	}
	docs := make([]embedder.Document, len(rows))
	for i, r := range rows {
		docs[i] = embedder.Document{ID: r.ID, Title: r.TitleJa, Body: songBody(r.Album, r.LyricsJa, r.Translation, r.Vocabulary)}
	}
	return docs, nil
}

// songBody joins the non-empty study fields into one embedding body, in a
// fixed order, separated by blank lines. Empty fields are skipped so a song
// with only a title embeds cleanly (embedText then embeds the title alone).
func songBody(parts ...string) string {
	nonEmpty := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	return strings.Join(nonEmpty, "\n\n")
}

// SetEmbedding persists the derived embedding for one shelf row. updated_at is
// left untouched — an embedding write is derived data, not an edit.
func (s *ShelfEmbeddingSource) SetEmbedding(ctx context.Context, id uuid.UUID, embedding pgvector.Vector) error {
	if err := s.store.q.SetSongEmbedding(ctx, db.SetSongEmbeddingParams{
		ID:        id,
		Embedding: &embedding,
	}); err != nil {
		return fmt.Errorf("setting embedding on song %s: %w", id, err)
	}
	return nil
}

// ReflectionEmbeddingSource embeds the song_reflections diary rows. The embed
// text is the reflection body alone: Title carries the body and Body is empty,
// so embedText returns the body verbatim.
type ReflectionEmbeddingSource struct {
	store *Store
}

// NewReflectionEmbeddingSource returns the reconciler source for the song
// reflection diary.
func NewReflectionEmbeddingSource(store *Store) *ReflectionEmbeddingSource {
	return &ReflectionEmbeddingSource{store: store}
}

// MissingEmbeddings returns up to limit reflection rows whose embedding is
// NULL, oldest first. The body is placed in Document.Title (with an empty
// Body) so embedText embeds the body alone — reflections have no title field.
func (s *ReflectionEmbeddingSource) MissingEmbeddings(ctx context.Context, limit int) ([]embedder.Document, error) {
	rows, err := s.store.q.SongReflectionsMissingEmbedding(ctx, int32(limit)) // #nosec G115 -- limit is a small reconciler batch size
	if err != nil {
		return nil, fmt.Errorf("listing song reflections missing embeddings: %w", err)
	}
	docs := make([]embedder.Document, len(rows))
	for i, r := range rows {
		docs[i] = embedder.Document{ID: r.ID, Title: r.Body}
	}
	return docs, nil
}

// SetEmbedding persists the derived embedding for one reflection row.
func (s *ReflectionEmbeddingSource) SetEmbedding(ctx context.Context, id uuid.UUID, embedding pgvector.Vector) error {
	if err := s.store.q.SetSongReflectionEmbedding(ctx, db.SetSongReflectionEmbeddingParams{
		ID:        id,
		Embedding: &embedding,
	}); err != nil {
		return fmt.Errorf("setting embedding on song reflection %s: %w", id, err)
	}
	return nil
}
