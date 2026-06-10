// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// Integration coverage for the note store's embedding surface against a
// real pgvector PostgreSQL: SemanticSearch ranks by cosine distance over
// caller-supplied vectors (no network), and MissingEmbeddings /
// SetEmbedding round-trip without touching updated_at.
//
// Run with:
//
//	go test -tags=integration ./internal/note/...
package note

import (
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pgvector/pgvector-go"

	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// setup truncates notes and seeds the agents the notes audit trigger and
// created_by FK depend on (mirrors the content package's integration
// setup — no server boots here, so the registry sync is a direct seed).
func setup(t *testing.T) *Store {
	t.Helper()
	if err := testdb.TruncateCtx(t.Context(), testPool,
		"activity_events", "notes"); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO agents (name, display_name, platform)
		 VALUES ('system', 'System', 'system'),
		        ('human', 'Human', 'human')
		 ON CONFLICT (name) DO NOTHING`); err != nil {
		t.Fatalf("seeding agents: %v", err)
	}
	return NewStore(testPool)
}

func seedNote(t *testing.T, s *Store, slug, title string) *Note {
	t.Helper()
	n, err := s.Create(t.Context(), &CreateParams{
		Slug:      slug,
		Title:     title,
		Body:      "body of " + slug,
		Kind:      KindMusing,
		CreatedBy: "human",
	})
	if err != nil {
		t.Fatalf("creating note %q: %v", slug, err)
	}
	return n
}

// vec1536 builds a 1536-dim vector whose leading elements are vals and
// the rest zero.
func vec1536(vals ...float32) pgvector.Vector {
	full := make([]float32, 1536)
	copy(full, vals)
	return pgvector.NewVector(full)
}

func TestSemanticSearch_CosineOrder(t *testing.T) {
	store := setup(t)
	ctx := t.Context()

	exact := seedNote(t, store, "exact-match", "Exact match")
	partial := seedNote(t, store, "partial-match", "Partial match")
	orthogonal := seedNote(t, store, "orthogonal", "Orthogonal")
	seedNote(t, store, "no-embedding", "No embedding")

	// Cosine similarity against the query e1: exact = 1, partial ≈ 0.707,
	// orthogonal = 0. The un-embedded note must not appear at all.
	if err := store.SetEmbedding(ctx, exact.ID, vec1536(1)); err != nil {
		t.Fatalf("SetEmbedding(exact): %v", err)
	}
	if err := store.SetEmbedding(ctx, partial.ID, vec1536(1, 1)); err != nil {
		t.Fatalf("SetEmbedding(partial): %v", err)
	}
	if err := store.SetEmbedding(ctx, orthogonal.ID, vec1536(0, 1)); err != nil {
		t.Fatalf("SetEmbedding(orthogonal): %v", err)
	}

	got, err := store.SemanticSearch(ctx, vec1536(1), 10)
	if err != nil {
		t.Fatalf("SemanticSearch() error = %v", err)
	}

	wantSlugs := []string{"exact-match", "partial-match", "orthogonal"}
	if len(got) != len(wantSlugs) {
		t.Fatalf("SemanticSearch() returned %d notes, want %d", len(got), len(wantSlugs))
	}
	for i, want := range wantSlugs {
		if got[i].Slug != want {
			t.Errorf("rank %d: slug = %q, want %q (cosine order)", i, got[i].Slug, want)
		}
	}
}

func TestMissingEmbeddings_SetEmbeddingRoundTrip(t *testing.T) {
	store := setup(t)
	ctx := t.Context()

	first := seedNote(t, store, "first-note", "First note")
	second := seedNote(t, store, "second-note", "Second note")

	missing, err := store.MissingEmbeddings(ctx, 10)
	if err != nil {
		t.Fatalf("MissingEmbeddings() error = %v", err)
	}
	if len(missing) != 2 {
		t.Fatalf("MissingEmbeddings() returned %d rows, want 2", len(missing))
	}

	if err := store.SetEmbedding(ctx, first.ID, vec1536(1)); err != nil {
		t.Fatalf("SetEmbedding() error = %v", err)
	}

	missing, err = store.MissingEmbeddings(ctx, 10)
	if err != nil {
		t.Fatalf("MissingEmbeddings() after set error = %v", err)
	}
	if len(missing) != 1 || missing[0].ID != second.ID {
		t.Fatalf("MissingEmbeddings() after set = %v, want only %s", missing, second.ID)
	}

	// SetEmbedding is a derived-data write: updated_at must not move.
	var updatedAt time.Time
	if err := testPool.QueryRow(ctx,
		`SELECT updated_at FROM notes WHERE id = $1`, first.ID).Scan(&updatedAt); err != nil {
		t.Fatalf("reading updated_at: %v", err)
	}
	if !updatedAt.Equal(first.UpdatedAt) {
		t.Errorf("updated_at = %v after SetEmbedding, want %v (unchanged)", updatedAt, first.UpdatedAt)
	}
}
