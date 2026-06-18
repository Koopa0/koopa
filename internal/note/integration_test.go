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
	"errors"
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
	return seedNoteBy(t, s, slug, title, "human")
}

// seedNoteBy seeds a note authored by createdBy. The agent must already
// exist (created_by FKs to agents.name) — seedAgent handles that.
func seedNoteBy(t *testing.T, s *Store, slug, title, createdBy string) *Note {
	t.Helper()
	n, err := s.Create(t.Context(), &CreateParams{
		Slug:      slug,
		Title:     title,
		Body:      "body of " + slug,
		Kind:      KindMusing,
		CreatedBy: createdBy,
	})
	if err != nil {
		t.Fatalf("creating note %q: %v", slug, err)
	}
	return n
}

// seedAgent inserts an agent row so notes can reference it via created_by.
func seedAgent(t *testing.T, name, platform string) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO agents (name, display_name, platform)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (name) DO NOTHING`, name, name, platform); err != nil {
		t.Fatalf("seeding agent %q: %v", name, err)
	}
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

func TestNotes_CreatedByFilter(t *testing.T) {
	store := setup(t)
	ctx := t.Context()

	// 'human' is seeded by setup; 'hermes' is the second author.
	seedAgent(t, "hermes", "claude-code")
	seedNoteBy(t, store, "hermes-one", "Hermes one", "hermes")
	seedNoteBy(t, store, "hermes-two", "Hermes two", "hermes")
	seedNoteBy(t, store, "human-one", "Human one", "human")

	page := Filter{Page: 1, PerPage: 50}

	// No filter: every author's notes are returned.
	all, total, err := store.Notes(ctx, page)
	if err != nil {
		t.Fatalf("Notes(no filter) error = %v", err)
	}
	if total != 3 || len(all) != 3 {
		t.Fatalf("Notes(no filter) = %d rows (total %d), want 3 rows (total 3)", len(all), total)
	}

	// created_by=hermes: only Hermes-authored notes.
	hermes := "hermes"
	f := page
	f.CreatedBy = &hermes
	got, total, err := store.Notes(ctx, f)
	if err != nil {
		t.Fatalf("Notes(created_by=hermes) error = %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("Notes(created_by=hermes) = %d rows (total %d), want 2 rows (total 2)", len(got), total)
	}
	for i := range got {
		if got[i].CreatedBy != "hermes" {
			t.Errorf("Notes(created_by=hermes)[%d].CreatedBy = %q, want %q", i, got[i].CreatedBy, "hermes")
		}
	}

	// created_by with no matching author: empty, not an error.
	none := "nonexistent-agent"
	f.CreatedBy = &none
	got, total, err = store.Notes(ctx, f)
	if err != nil {
		t.Fatalf("Notes(created_by=nonexistent) error = %v", err)
	}
	if total != 0 || len(got) != 0 {
		t.Fatalf("Notes(created_by=nonexistent) = %d rows (total %d), want 0 rows (total 0)", len(got), total)
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

// TestStore_InvalidInput verifies that a value the database (or the store's own
// blank-title guard) rejects surfaces as ErrInvalidInput — which the HTTP
// handler maps to 400 and the MCP create_note/update_note tools report as an
// invalid-input message — instead of a wrapped error rendered as an opaque 500.
// The store is the shared write path for both callers, so mapping it here
// covers both. Coverage: a malformed slug (chk_note_slug_format 23514) and a
// blank title (chk_note_title_not_blank 23514) on Create, and the same two on
// Update (where a present-yet-blank title is caught by the store's pre-check).
func TestStore_InvalidInput(t *testing.T) {
	store := setup(t)
	ctx := t.Context()

	blank := "   "
	badSlug := "Not A Valid Slug!"

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create with malformed slug (chk_note_slug_format 23514)",
			run: func() error {
				_, err := store.Create(ctx, &CreateParams{
					Slug:      badSlug,
					Title:     "Valid title",
					Body:      "body",
					Kind:      KindMusing,
					CreatedBy: "human",
				})
				return err
			},
		},
		{
			name: "create with blank title (chk_note_title_not_blank 23514)",
			run: func() error {
				_, err := store.Create(ctx, &CreateParams{
					Slug:      "valid-slug",
					Title:     blank,
					Body:      "body",
					Kind:      KindMusing,
					CreatedBy: "human",
				})
				return err
			},
		},
		{
			name: "update to malformed slug (chk_note_slug_format 23514)",
			run: func() error {
				existing := seedNote(t, store, "update-slug-target", "Update Slug Target")
				_, err := store.Update(ctx, existing.ID, UpdateParams{Slug: &badSlug})
				return err
			},
		},
		{
			name: "update to blank title (store blank-title guard)",
			run: func() error {
				existing := seedNote(t, store, "update-title-target", "Update Title Target")
				_, err := store.Update(ctx, existing.ID, UpdateParams{Title: &blank})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err = %v, want ErrInvalidInput", err)
			}
		})
	}
}
