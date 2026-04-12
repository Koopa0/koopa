//go:build integration

package bookmark_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa0.dev/internal/testdb"
)

// TestBackfillMigration verifies migration 006_bookmarks_backfill on a
// real PostgreSQL instance. testdb.NewPool runs all migrations on a
// fresh container, so by the time this test starts the DB schema
// includes bookmarks (005) and the backfill migration (006) has already
// run on an empty contents table — a no-op.
//
// The test then seeds one feed → feed_entry → contents(type=bookmark)
// chain (plus a topic and tag), re-executes the 006 up SQL against the
// pool, and asserts that the backfill produced the expected bookmark,
// junction rows, and tombstone. Re-executing is safe because every
// write in 006 is idempotent (ON CONFLICT DO NOTHING / jsonb_set).
//
// The reverse side is exercised by running the down SQL and asserting
// the backfill is cleanly removed.
func TestBackfillMigration(t *testing.T) {
	pool := testdb.NewPool(t)
	ctx := t.Context()

	// --- seed ---
	url := "https://example.com/article-about-go-concurrency"
	urlHash := sha256Hex(url)
	title := "Article About Go Concurrency"
	slug := "article-about-go-concurrency"
	body := "**Source:** " + url + "\n\n**Comment:** Nice overview of worker pools."
	excerpt := "Nice overview of worker pools."

	feedID := seedFeed(t, pool, "Example Feed", "https://example.com/feed.xml")
	topicID := seedTopic(t, pool, "go-concurrency", "Go Concurrency")
	tagID := seedTag(t, pool, "golang")
	contentID := seedBookmarkContent(t, pool, slug, title, body, excerpt)
	seedContentTopic(t, pool, contentID, topicID)
	seedContentTag(t, pool, contentID, tagID)
	feedEntryID := seedFeedEntry(t, pool, feedID, url, urlHash, title, contentID)

	// --- execute backfill SQL (re-run, exercises the actual statement) ---
	execMigrationFile(t, ctx, pool, "006_bookmarks_backfill.up.sql")

	// --- assert: exactly one bookmark created from this content ---
	var (
		gotID              uuid.UUID
		gotURL             string
		gotURLHash         string
		gotSlug            string
		gotTitle           string
		gotExcerpt         string
		gotNote            string
		gotSourceType      string
		gotSourceEntryID   *uuid.UUID
		gotCuratedBy       string
		gotIsPublic        bool
		gotLegacyContentID *uuid.UUID
	)
	err := pool.QueryRow(ctx, `
        SELECT id, url, url_hash, slug, title, excerpt, note,
               source_type, source_feed_entry_id, curated_by, is_public,
               legacy_content_id
        FROM bookmarks
        WHERE legacy_content_id = $1
    `, contentID).Scan(
		&gotID, &gotURL, &gotURLHash, &gotSlug, &gotTitle, &gotExcerpt,
		&gotNote, &gotSourceType, &gotSourceEntryID, &gotCuratedBy,
		&gotIsPublic, &gotLegacyContentID,
	)
	if err != nil {
		t.Fatalf("selecting backfilled bookmark: %v", err)
	}

	if diff := cmp.Diff(url, gotURL); diff != "" {
		t.Errorf("url mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(urlHash, gotURLHash); diff != "" {
		t.Errorf("url_hash mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(slug, gotSlug); diff != "" {
		t.Errorf("slug mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(title, gotTitle); diff != "" {
		t.Errorf("title mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(excerpt, gotExcerpt); diff != "" {
		t.Errorf("excerpt mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(body, gotNote); diff != "" {
		t.Errorf("note (was body) mismatch (-want +got):\n%s", diff)
	}
	if gotSourceType != "rss" {
		t.Errorf("source_type = %q, want %q", gotSourceType, "rss")
	}
	if gotSourceEntryID == nil || *gotSourceEntryID != feedEntryID {
		t.Errorf("source_feed_entry_id = %v, want %v", gotSourceEntryID, feedEntryID)
	}
	if gotCuratedBy != "human" {
		t.Errorf("curated_by = %q, want %q", gotCuratedBy, "human")
	}
	if gotLegacyContentID == nil || *gotLegacyContentID != contentID {
		t.Errorf("legacy_content_id = %v, want %v", gotLegacyContentID, contentID)
	}

	// --- assert: bookmark_topics carried the relationship ---
	var topicCount int
	if err := pool.QueryRow(ctx, `
        SELECT COUNT(*) FROM bookmark_topics
        WHERE bookmark_id = $1 AND topic_id = $2
    `, gotID, topicID).Scan(&topicCount); err != nil {
		t.Fatalf("counting bookmark_topics: %v", err)
	}
	if topicCount != 1 {
		t.Errorf("bookmark_topics count = %d, want 1", topicCount)
	}

	// --- assert: bookmark_tags carried the relationship ---
	var tagCount int
	if err := pool.QueryRow(ctx, `
        SELECT COUNT(*) FROM bookmark_tags
        WHERE bookmark_id = $1 AND tag_id = $2
    `, gotID, tagID).Scan(&tagCount); err != nil {
		t.Fatalf("counting bookmark_tags: %v", err)
	}
	if tagCount != 1 {
		t.Errorf("bookmark_tags count = %d, want 1", tagCount)
	}

	// --- assert: contents.ai_metadata tombstone pointing at bookmark ---
	var tombstone *string
	if err := pool.QueryRow(ctx, `
        SELECT ai_metadata ->> 'migrated_to_bookmark_id'
        FROM contents
        WHERE id = $1
    `, contentID).Scan(&tombstone); err != nil {
		t.Fatalf("reading tombstone: %v", err)
	}
	if tombstone == nil || *tombstone != gotID.String() {
		t.Errorf("tombstone = %v, want %s", tombstone, gotID)
	}

	// --- down migration: reverse the backfill ---
	execMigrationFile(t, ctx, pool, "006_bookmarks_backfill.down.sql")

	var remainingBookmarks int
	if err := pool.QueryRow(ctx, `
        SELECT COUNT(*) FROM bookmarks WHERE legacy_content_id IS NOT NULL
    `).Scan(&remainingBookmarks); err != nil {
		t.Fatalf("counting remaining bookmarks: %v", err)
	}
	if remainingBookmarks != 0 {
		t.Errorf("bookmarks with legacy_content_id after down = %d, want 0", remainingBookmarks)
	}

	var tombstoneAfter *string
	if err := pool.QueryRow(ctx, `
        SELECT ai_metadata ->> 'migrated_to_bookmark_id'
        FROM contents
        WHERE id = $1
    `, contentID).Scan(&tombstoneAfter); err != nil {
		t.Fatalf("reading tombstone after down: %v", err)
	}
	if tombstoneAfter != nil {
		t.Errorf("tombstone after down = %v, want nil", tombstoneAfter)
	}
}

// --- helpers ---

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func seedFeed(t *testing.T, pool *pgxpool.Pool, name, url string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(t.Context(), `
        INSERT INTO feeds (name, url, schedule, enabled)
        VALUES ($1, $2, 'daily', true)
        RETURNING id
    `, name, url).Scan(&id)
	if err != nil {
		t.Fatalf("seed feed: %v", err)
	}
	return id
}

func seedTopic(t *testing.T, pool *pgxpool.Pool, slug, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(t.Context(), `
        INSERT INTO topics (slug, name) VALUES ($1, $2) RETURNING id
    `, slug, name).Scan(&id)
	if err != nil {
		t.Fatalf("seed topic: %v", err)
	}
	return id
}

func seedTag(t *testing.T, pool *pgxpool.Pool, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(t.Context(), `
        INSERT INTO tags (name, slug) VALUES ($1, $1) RETURNING id
    `, name).Scan(&id)
	if err != nil {
		t.Fatalf("seed tag: %v", err)
	}
	return id
}

func seedBookmarkContent(t *testing.T, pool *pgxpool.Pool, slug, title, body, excerpt string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(t.Context(), `
        INSERT INTO contents (slug, title, body, excerpt, type, status, review_level, is_public)
        VALUES ($1, $2, $3, $4, 'bookmark', 'published', 'light', true)
        RETURNING id
    `, slug, title, body, excerpt).Scan(&id)
	if err != nil {
		t.Fatalf("seed bookmark content: %v", err)
	}
	return id
}

func seedContentTopic(t *testing.T, pool *pgxpool.Pool, contentID, topicID uuid.UUID) {
	t.Helper()
	_, err := pool.Exec(t.Context(), `
        INSERT INTO content_topics (content_id, topic_id) VALUES ($1, $2)
    `, contentID, topicID)
	if err != nil {
		t.Fatalf("seed content_topic: %v", err)
	}
}

func seedContentTag(t *testing.T, pool *pgxpool.Pool, contentID, tagID uuid.UUID) {
	t.Helper()
	_, err := pool.Exec(t.Context(), `
        INSERT INTO content_tags (content_id, tag_id) VALUES ($1, $2)
    `, contentID, tagID)
	if err != nil {
		t.Fatalf("seed content_tag: %v", err)
	}
}

func seedFeedEntry(t *testing.T, pool *pgxpool.Pool, feedID uuid.UUID, url, urlHash, title string, curatedContentID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(t.Context(), `
        INSERT INTO feed_entries (feed_id, source_url, url_hash, title, status, curated_content_id)
        VALUES ($1, $2, $3, $4, 'curated', $5)
        RETURNING id
    `, feedID, url, urlHash, title, curatedContentID).Scan(&id)
	if err != nil {
		t.Fatalf("seed feed_entry: %v", err)
	}
	return id
}

func execMigrationFile(t *testing.T, ctx context.Context, pool *pgxpool.Pool, filename string) {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "migrations", filename)
	b, err := os.ReadFile(path) // #nosec G304 — test-only, path comes from constant
	if err != nil {
		t.Fatalf("reading %s: %v", filename, err)
	}
	if _, err := pool.Exec(ctx, string(b)); err != nil {
		t.Fatalf("executing %s: %v", filename, err)
	}
}
