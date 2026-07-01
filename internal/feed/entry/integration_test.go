// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go drives entry.Store.CreateNewItems against a real
// PostgreSQL (testcontainers) — the batch dedup+insert that replaced the
// collector's old per-item SELECT-then-INSERT loop. Nothing in this
// codebase previously exercised the dedup path against a real database.
//
// Run with:
//
//	go test -count=1 -tags=integration ./internal/feed/entry/...
package entry_test

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/feed/entry"
	"github.com/Koopa0/koopa/internal/testdb"
	koopaurl "github.com/Koopa0/koopa/internal/url"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.NewPool()
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func truncate(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(), `TRUNCATE feed_entries CASCADE`); err != nil {
		t.Fatalf("truncating feed_entries: %v", err)
	}
}

func hashOf(t *testing.T, rawURL string) string {
	t.Helper()
	h, err := koopaurl.Hash(rawURL)
	if err != nil {
		t.Fatalf("hashing %q: %v", rawURL, err)
	}
	return h
}

type storedRow struct {
	SourceURL   string
	Title       string
	PublishedAt *time.Time
}

func readRow(t *testing.T, urlHash string) storedRow {
	t.Helper()
	var r storedRow
	if err := testPool.QueryRow(t.Context(),
		`SELECT source_url, title, published_at FROM feed_entries WHERE url_hash = $1`, urlHash,
	).Scan(&r.SourceURL, &r.Title, &r.PublishedAt); err != nil {
		t.Fatalf("reading row for hash %s: %v", urlHash, err)
	}
	return r
}

// TestIntegration_CreateNewItems_DedupAndNullPublishedAt drives the batch
// insert with a mix of a published-date item and a no-date item, confirming
// (a) both land with the right per-row data — the thing a transposed
// unnest() zip across 6 parallel arrays would get wrong without erroring —
// and (b) published_at is a true SQL NULL, not a zero-value timestamp, when
// the source item had no date (the has_published sidecar array).
func TestIntegration_CreateNewItems_DedupAndNullPublishedAt(t *testing.T) {
	truncate(t)
	store := entry.NewStore(testPool)
	// feed_id is a foreign key, so a random uuid would violate it, but it's
	// nullable (ON DELETE SET NULL) — pass nil rather than pre-seed a feeds
	// row, since CreateNewItems doesn't depend on a real feed row to prove
	// the dedup and per-row data correctness this test targets.

	dated := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	urlA := "https://example.com/a"
	urlB := "https://example.com/b"

	ids, err := store.CreateNewItems(t.Context(), nil, []entry.NewItem{
		{SourceURL: urlA, Title: "Article A", OriginalContent: "content a", URLHash: hashOf(t, urlA), PublishedAt: &dated},
		{SourceURL: urlB, Title: "Article B", OriginalContent: "content b", URLHash: hashOf(t, urlB), PublishedAt: nil},
	})
	if err != nil {
		t.Fatalf("CreateNewItems: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("CreateNewItems returned %d ids, want 2", len(ids))
	}

	gotA := readRow(t, hashOf(t, urlA))
	wantA := storedRow{SourceURL: urlA, Title: "Article A", PublishedAt: &dated}
	if diff := cmp.Diff(wantA, gotA, cmpopts.EquateApproxTime(time.Second)); diff != "" {
		t.Errorf("row A mismatch (-want +got):\n%s", diff)
	}

	gotB := readRow(t, hashOf(t, urlB))
	if gotB.SourceURL != urlB || gotB.Title != "Article B" {
		t.Errorf("row B = %+v, want SourceURL=%q Title=%q", gotB, urlB, "Article B")
	}
	if gotB.PublishedAt != nil {
		t.Errorf("row B published_at = %v, want nil (no date on the source item)", gotB.PublishedAt)
	}

	// Re-run with one duplicate (A again) and one genuinely new item (C).
	// ON CONFLICT (url_hash) DO NOTHING must silently absorb A — no error,
	// no duplicate row — while C still lands and its id comes back.
	urlC := "https://example.com/c"
	ids2, err := store.CreateNewItems(t.Context(), nil, []entry.NewItem{
		{SourceURL: urlA, Title: "Article A (refetched)", OriginalContent: "stale", URLHash: hashOf(t, urlA), PublishedAt: &dated},
		{SourceURL: urlC, Title: "Article C", OriginalContent: "content c", URLHash: hashOf(t, urlC), PublishedAt: nil},
	})
	if err != nil {
		t.Fatalf("CreateNewItems (dedup round): %v", err)
	}
	if len(ids2) != 1 {
		t.Fatalf("CreateNewItems (dedup round) returned %d ids, want 1 (only C is new)", len(ids2))
	}

	var total int
	if err := testPool.QueryRow(t.Context(), `SELECT COUNT(*) FROM feed_entries`).Scan(&total); err != nil {
		t.Fatalf("counting feed_entries: %v", err)
	}
	if total != 3 {
		t.Errorf("feed_entries count = %d, want 3 (A, B, C — no duplicate row for the re-sent A)", total)
	}
	if got := readRow(t, hashOf(t, urlA)); got.Title != "Article A" {
		t.Errorf("row A title after dedup re-send = %q, want %q (ON CONFLICT DO NOTHING must not overwrite)", got.Title, "Article A")
	}
}

// TestIntegration_CreateNewItems_Empty asserts the empty-slice fast path is
// a true no-op: no query issued, nil result, no error.
func TestIntegration_CreateNewItems_Empty(t *testing.T) {
	truncate(t)
	store := entry.NewStore(testPool)

	ids, err := store.CreateNewItems(t.Context(), nil, nil)
	if err != nil {
		t.Fatalf("CreateNewItems(empty): %v", err)
	}
	if ids != nil {
		t.Errorf("CreateNewItems(empty) ids = %v, want nil", ids)
	}
}
