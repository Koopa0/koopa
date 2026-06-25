// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// Integration coverage for the embedding reconciler against a real
// pgvector PostgreSQL: RunOnce drains contents rows with NULL embeddings
// through the real store methods, archived contents are skipped, and the
// embedding-only UPDATE neither bumps updated_at nor writes activity_events
// rows.
//
// External test package: content imports embedder for the Source seam, so
// an in-package test importing it back would cycle.
//
// Run with:
//
//	go test -tags=integration ./internal/embedder/...
package embedder_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/embedder"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.NewPool()
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// stubTextEmbedder returns a fixed-dimension vector without network
// access; element 0 carries the input length so vectors differ per row.
type stubTextEmbedder struct{}

func (stubTextEmbedder) Embed(_ context.Context, text string) ([]float32, error) {
	vec := make([]float32, embedder.Dimension)
	vec[0] = float32(len(text))
	return vec, nil
}

// setup truncates the tables this suite writes and seeds the agents the
// audit triggers depend on (mirrors the content package's integration
// setup — these tests don't boot a server, so the registry sync is done
// as a direct seed).
func setup(t *testing.T) {
	t.Helper()
	if err := testdb.TruncateCtx(t.Context(), testPool,
		"activity_events", "contents"); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO agents (name, display_name, platform)
		 VALUES ('human', 'Human', 'human')
		 ON CONFLICT (name) DO NOTHING`); err != nil {
		t.Fatalf("seeding agents: %v", err)
	}
}

func seedContent(t *testing.T, slug, title, body, status string) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO contents (slug, title, body, type, status) VALUES ($1, $2, $3, 'til', $4)`,
		slug, title, body, status); err != nil {
		t.Fatalf("seeding content %q: %v", slug, err)
	}
}

func TestReconcilerRunOnce_DrainsContents(t *testing.T) {
	setup(t)
	seedContent(t, "active-one", "Active one", "body one", "draft")
	seedContent(t, "active-two", "Active two", "body two", "draft")
	seedContent(t, "archived-row", "Archived row", "buried body", "archived")

	var auditRowsBefore int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM activity_events`).Scan(&auditRowsBefore); err != nil {
		t.Fatalf("counting activity_events: %v", err)
	}
	var contentUpdatedBefore time.Time
	if err := testPool.QueryRow(t.Context(),
		`SELECT updated_at FROM contents WHERE slug = 'active-one'`).Scan(&contentUpdatedBefore); err != nil {
		t.Fatalf("reading content updated_at: %v", err)
	}

	r := embedder.NewReconciler(stubTextEmbedder{}, slog.New(slog.DiscardHandler),
		embedder.NamedSource{Name: "contents", Source: content.NewStore(testPool)})

	got, err := r.RunOnce(t.Context())
	if err != nil {
		t.Fatalf("RunOnce() error = %v, want nil", err)
	}
	want := embedder.Result{BySource: map[string]int{"contents": 2}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("RunOnce() result mismatch (-want +got):\n%s", diff)
	}

	// Every non-archived row carries a 1536-dim vector; archived stays NULL.
	assertDims := func(table, slug string) {
		t.Helper()
		var dims int
		if err := testPool.QueryRow(t.Context(),
			`SELECT vector_dims(embedding) FROM `+table+` WHERE slug = $1`, slug).Scan(&dims); err != nil {
			t.Fatalf("reading %s %q embedding dims: %v", table, slug, err)
		}
		if dims != embedder.Dimension {
			t.Errorf("%s %q embedding dims = %d, want %d", table, slug, dims, embedder.Dimension)
		}
	}
	assertDims("contents", "active-one")
	assertDims("contents", "active-two")

	var archivedHasEmbedding bool
	if err := testPool.QueryRow(t.Context(),
		`SELECT embedding IS NOT NULL FROM contents WHERE slug = 'archived-row'`).Scan(&archivedHasEmbedding); err != nil {
		t.Fatalf("reading archived embedding: %v", err)
	}
	if archivedHasEmbedding {
		t.Error("archived content got an embedding, want NULL (skipped)")
	}

	// Embedding writes are derived data: no audit rows, no updated_at bump.
	var auditRowsAfter int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM activity_events`).Scan(&auditRowsAfter); err != nil {
		t.Fatalf("counting activity_events: %v", err)
	}
	if auditRowsAfter != auditRowsBefore {
		t.Errorf("activity_events rows = %d after RunOnce, want %d (embedding UPDATE must not audit)",
			auditRowsAfter, auditRowsBefore)
	}
	var contentUpdatedAfter time.Time
	if err := testPool.QueryRow(t.Context(),
		`SELECT updated_at FROM contents WHERE slug = 'active-one'`).Scan(&contentUpdatedAfter); err != nil {
		t.Fatalf("reading content updated_at: %v", err)
	}
	if !contentUpdatedAfter.Equal(contentUpdatedBefore) {
		t.Errorf("content updated_at = %v after RunOnce, want %v (unchanged)",
			contentUpdatedAfter, contentUpdatedBefore)
	}

	// A second pass finds nothing left to do — the source is still reported
	// with a zero count (BySource always carries an entry per wired source).
	again, err := r.RunOnce(t.Context())
	if err != nil {
		t.Fatalf("second RunOnce() error = %v, want nil", err)
	}
	want = embedder.Result{BySource: map[string]int{"contents": 0}}
	if diff := cmp.Diff(want, again); diff != "" {
		t.Errorf("second RunOnce() result mismatch (-want +got):\n%s", diff)
	}
}
