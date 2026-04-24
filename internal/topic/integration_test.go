//go:build integration

// Integration coverage for the RelatedTagsForTopic runtime fix (V4).
// The old query joined contents → content_tags by an incorrect alias
// and silently returned an empty set, which the UI surfaced as a
// permanent "no related tags" state. After V4 the query joins through
// content_topics and content_tags correctly; this test seeds a topic, a
// published content row, a tag, and both junctions, then asserts the
// topic's RelatedTags returns the seeded tag with count=1.
//
// Run with:
//
//	go test -tags=integration ./internal/topic/...
package topic_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/testdb"
	"github.com/Koopa0/koopa/internal/topic"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool

	// contents insert fires an audit trigger that writes to
	// activity_events.actor (FK on agents). Seed the builtin registry so
	// the fallback 'system' actor is present.
	registry := agent.NewBuiltinRegistry()
	if _, err := agent.SyncToTable(context.Background(), registry, agent.NewStore(pool), slog.Default()); err != nil {
		slog.Default().Error("agent.SyncToTable", "error", err)
		cleanup()
		os.Exit(1)
	}

	code := m.Run()
	cleanup()
	os.Exit(code)
}

// seedRelatedTagsFixture inserts one topic, one tag, one published
// public content row, and the two junction rows that tie them together.
// Returns (topicID, tagSlug).
func seedRelatedTagsFixture(t *testing.T, pool *pgxpool.Pool) (topicID uuid.UUID, tagSlug string) {
	t.Helper()

	err := pool.QueryRow(t.Context(),
		`INSERT INTO topics (slug, name, description, sort_order)
		 VALUES ('testing', 'Testing', 'Integration tests', 100)
		 RETURNING id`,
	).Scan(&topicID)
	if err != nil {
		t.Fatalf("seeding topic: %v", err)
	}

	var tagID uuid.UUID
	err = pool.QueryRow(t.Context(),
		`INSERT INTO tags (slug, name, description)
		 VALUES ('integration-test', 'Integration Test', 'Tag for integration tests')
		 RETURNING id`,
	).Scan(&tagID)
	if err != nil {
		t.Fatalf("seeding tag: %v", err)
	}

	var contentID uuid.UUID
	err = pool.QueryRow(t.Context(),
		`INSERT INTO contents
		     (slug, title, body, type, status, is_public, published_at)
		 VALUES
		     ('related-tags-fixture', 'Related Tags Fixture', 'body',
		      'article'::content_type, 'published'::content_status, true, now())
		 RETURNING id`,
	).Scan(&contentID)
	if err != nil {
		t.Fatalf("seeding content: %v", err)
	}

	if _, err := pool.Exec(t.Context(),
		`INSERT INTO content_topics (content_id, topic_id) VALUES ($1, $2)`,
		contentID, topicID,
	); err != nil {
		t.Fatalf("seeding content_topics: %v", err)
	}
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO content_tags (content_id, tag_id) VALUES ($1, $2)`,
		contentID, tagID,
	); err != nil {
		t.Fatalf("seeding content_tags: %v", err)
	}

	tagSlug = "integration-test"
	return topicID, tagSlug
}

// TestRelatedTagsForTopic_ReturnsTagsViaJunction locks the V4 fix: with
// both junctions correctly seeded, the topic's RelatedTags query must
// surface the tag slug and a count of one. A regression that restores
// the broken JOIN (or drops the junction walk) shows up as len == 0
// here.
func TestRelatedTagsForTopic_ReturnsTagsViaJunction(t *testing.T) {
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE content_tags, content_topics, contents, tags, topics CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	topicID, wantTag := seedRelatedTagsFixture(t, testPool)

	store := topic.NewStore(testPool)
	tags, err := store.RelatedTags(t.Context(), topicID, 5)
	if err != nil {
		t.Fatalf("RelatedTags: %v", err)
	}

	if len(tags) != 1 {
		t.Fatalf("RelatedTags returned %d rows, want 1 (V4 regression: junction walk broken)", len(tags))
	}
	if tags[0].Tag != wantTag {
		t.Errorf("tag = %q, want %q", tags[0].Tag, wantTag)
	}
	if tags[0].Count != 1 {
		t.Errorf("count = %d, want 1", tags[0].Count)
	}
}
