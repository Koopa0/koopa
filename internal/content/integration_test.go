//go:build integration

package content

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

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

func setup(t *testing.T) *Store {
	t.Helper()
	// Junction + dependent tables first, then contents, then the catalogs
	// that contents/learning_targets reference (topics / concepts).
	// learning_targets references contents (content_id ON DELETE SET NULL)
	// and concepts (via learning_target_concepts), so it must be truncated
	// before concepts.
	if err := testdb.TruncateCtx(t.Context(), testPool,
		"content_concepts", "content_topics",
		"learning_target_concepts", "learning_targets",
		"contents", "concepts", "topics"); err != nil {
		t.Fatal(err)
	}
	// Seed the 'system' agent so the contents/learning_attempts AFTER
	// triggers (which INSERT into activity_events with actor=current_actor()
	// and fall back to 'system' when koopa.actor is not SET LOCAL) do not
	// hit activity_events_actor_fkey. In production cmd/mcp wires this via
	// agent.SyncToTable(BuiltinAgents()); integration tests don't boot the
	// MCP server so the seed is done directly.
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO agents (name, display_name, platform)
		 VALUES ('system', 'System', 'system')
		 ON CONFLICT (name) DO NOTHING`); err != nil {
		t.Fatalf("seeding system agent: %v", err)
	}
	return NewStore(testPool)
}

// seedLearningTarget helper has been removed alongside the
// 1:1 learning_targets.content_id FK. Target↔content attach now goes
// through learning_target_contents (learning package); integration
// coverage lives in the learning package's own tests.

// seedConcept inserts a concepts row via SQL. Same rationale as seedTopic:
// avoid importing the learning package to dodge an import cycle.
func seedConcept(t *testing.T, pool *pgxpool.Pool, domain, slug, name, kind string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(t.Context(),
		`INSERT INTO concepts (domain, slug, name, kind) VALUES ($1, $2, $3, $4) RETURNING id`,
		domain, slug, name, kind,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seedConcept(%q/%q) error: %v", domain, slug, err)
	}
	return id
}

// contentIDForTarget reads back learning_targets.content_id for atomicity
// assertions in the note+learning_target test.
// contentIDForTarget helper removed — learning_targets.content_id no
// longer exists. Caller used to assert 1:1 atomicity; target-writeup
// linkage is now N:M via learning_target_contents + learning_target_notes,
// tested from the learning package.

// contentConceptIDs reads back concept_id rows from the content_concepts
// junction for the given content row, for atomicity assertions.
func contentConceptIDs(t *testing.T, pool *pgxpool.Pool, contentID uuid.UUID) []uuid.UUID {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT concept_id FROM content_concepts WHERE content_id = $1 ORDER BY concept_id`,
		contentID,
	)
	if err != nil {
		t.Fatalf("contentConceptIDs(%s) error: %v", contentID, err)
	}
	defer rows.Close()
	ids := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("contentConceptIDs scan: %v", err)
		}
		ids = append(ids, id)
	}
	return ids
}

// cmpContentOpts are reusable cmp options for Content comparison.
// Timestamps are compared with 1-second tolerance, and Topics slice ordering is ignored.
var cmpContentOpts = cmp.Options{
	cmpopts.EquateApproxTime(time.Second),
	cmpopts.SortSlices(func(a, b TopicRef) bool { return a.Slug < b.Slug }),
}

// topicRow holds the minimal fields returned by seedTopic.
type topicRow struct {
	ID   uuid.UUID
	Slug string
	Name string
}

// seedTopic inserts a topic directly via SQL to avoid importing the topic package
// (which would create an import cycle: content_test -> topic -> content).
func seedTopic(t *testing.T, pool *pgxpool.Pool, slug, name string) topicRow {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(t.Context(),
		`INSERT INTO topics (slug, name, description) VALUES ($1, $2, $3) RETURNING id`,
		slug, name, "test topic",
	).Scan(&id)
	if err != nil {
		t.Fatalf("seedTopic(%q) error: %v", slug, err)
	}
	return topicRow{ID: id, Slug: slug, Name: name}
}

func TestStore_CreateContent_and_Content(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	tp := seedTopic(t, testPool, "golang", "Go Language")

	params := &CreateParams{
		Slug:           "test-article",
		Title:          "Test Article",
		Body:           "This is the body of the test article.",
		Excerpt:        "A short excerpt.",
		Type:           TypeArticle,
		Status:         StatusDraft,
		TopicIDs:       []uuid.UUID{tp.ID},
		ReadingTimeMin: 5,
	}

	created, err := s.CreateContent(ctx, params)
	if err != nil {
		t.Fatalf("CreateContent() error: %v", err)
	}

	if created.ID == uuid.Nil {
		t.Fatal("CreateContent() returned nil ID")
	}
	if created.Status != StatusDraft {
		t.Errorf("CreateContent() status = %q, want %q", created.Status, StatusDraft)
	}

	// Round-trip: read back by ID.
	got, err := s.Content(ctx, created.ID)
	if err != nil {
		t.Fatalf("Content(%s) error: %v", created.ID, err)
	}

	// IsPublic defaults to false post notes-unification (private-by-default
	// per chk_content_public_requires_published — publishing is an atomic
	// flip of status + is_public + published_at via PublishContent).
	// Tags come from a separate tag-resolution path (not CreateParams),
	// so a freshly created row always reads back with Tags=[].
	want := &Content{
		ID:             created.ID,
		Slug:           "test-article",
		Title:          "Test Article",
		Body:           "This is the body of the test article.",
		Excerpt:        "A short excerpt.",
		Type:           TypeArticle,
		Status:         StatusDraft,
		Tags:           []string{},
		Topics:         []TopicRef{{ID: tp.ID, Slug: "golang", Name: "Go Language"}},
		IsPublic:       false,
		ReadingTimeMin: 5,
		CreatedAt:      created.CreatedAt,
		UpdatedAt:      created.UpdatedAt,
	}

	if diff := cmp.Diff(want, got, cmpContentOpts); diff != "" {
		t.Errorf("Content(%s) mismatch (-want +got):\n%s", created.ID, diff)
	}
}

// TestStore_CreateContent_DuplicateSlug verifies slug collisions produce a
// structured *SlugConflictError (not the bare ErrConflict) so callers —
// notably learning-studio via MCP — can decide between "update the same
// note" and "pick a new slug for a revisit" without re-querying by slug.
func TestStore_CreateContent_DuplicateSlug(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	params := &CreateParams{
		Slug:    "duplicate-slug",
		Title:   "First",
		Body:    "body",
		Excerpt: "excerpt",
		Type:    TypeTIL,
		Status:  StatusDraft,
	}

	first, err := s.CreateContent(ctx, params)
	if err != nil {
		t.Fatalf("CreateContent() first call error: %v", err)
	}

	// Second create with the same slug must return *SlugConflictError
	// carrying the first row's id.
	_, err = s.CreateContent(ctx, params)
	if err == nil {
		t.Fatalf("CreateContent(duplicate slug) = nil, want *SlugConflictError")
	}
	var slugErr *SlugConflictError
	if !errors.As(err, &slugErr) {
		t.Fatalf("CreateContent(duplicate slug) err type = %T (%v), want *SlugConflictError", err, err)
	}
	if slugErr.Slug != params.Slug {
		t.Errorf("SlugConflictError.Slug = %q, want %q", slugErr.Slug, params.Slug)
	}
	if slugErr.ContentID != first.ID {
		t.Errorf("SlugConflictError.ContentID = %s, want %s", slugErr.ContentID, first.ID)
	}
}

// TestStore_CreateContent_DuplicateSlug_InTx verifies the structured
// *SlugConflictError survives when CreateContent runs inside a pgx.Tx.
// A 23505 unique-violation aborts the enclosing tx in PostgreSQL, which
// used to make the post-insert slug lookup fail with SQLSTATE 25P02 and
// silently downgrade the error to the bare ErrConflict sentinel. The fix
// pre-resolves the existing id before the INSERT so the enrichment path
// never touches an aborted tx.
func TestStore_CreateContent_DuplicateSlug_InTx(t *testing.T) {
	// Seed the first row on a pool-backed store (committed, visible to
	// the later tx).
	s := setup(t)
	ctx := t.Context()

	params := &CreateParams{
		Slug:    "duplicate-slug-in-tx",
		Title:   "First",
		Body:    "body",
		Excerpt: "excerpt",
		Type:    TypeTIL,
		Status:  StatusDraft,
	}
	first, err := s.CreateContent(ctx, params)
	if err != nil {
		t.Fatalf("CreateContent() first call error: %v", err)
	}

	// Open a tx, run CreateContent through a tx-scoped store, expect
	// *SlugConflictError even though we're inside a tx that the 23505
	// aborts.
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = NewStore(tx).CreateContent(ctx, params)
	if err == nil {
		t.Fatalf("CreateContent(duplicate slug, in tx) = nil, want *SlugConflictError")
	}
	var slugErr *SlugConflictError
	if !errors.As(err, &slugErr) {
		t.Fatalf("CreateContent(duplicate slug, in tx) err type = %T (%v), want *SlugConflictError", err, err)
	}
	if slugErr.Slug != params.Slug {
		t.Errorf("SlugConflictError.Slug = %q, want %q", slugErr.Slug, params.Slug)
	}
	if slugErr.ContentID != first.ID {
		t.Errorf("SlugConflictError.ContentID = %s, want %s", slugErr.ContentID, first.ID)
	}
}

// TestStore_CreateContent_LearningTargetNotFound, _NoteWithLearningTarget,
// and _NoteWithConcepts (with note+learning_target wiring) were removed in
// schema cleanup when the 1:1 learning_targets.content_id FK was dropped.
// Target↔writeup linkage is now N:M via learning_target_contents +
// learning_target_notes junctions; integration coverage for those lives
// in the learning package's tests. The bare content_concepts junction
// path (below) still stands on its own.

// TestStore_CreateContent_ArticleWithConcepts verifies CreateContent
// atomically inserts content_concepts rows for every ConceptID attached
// to a public content row.
func TestStore_CreateContent_ArticleWithConcepts(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	cid1 := seedConcept(t, testPool, "leetcode", "binary-search-basic", "Binary Search (basic)", "pattern")
	cid2 := seedConcept(t, testPool, "leetcode", "binary-search-on-rotated", "Binary Search (rotated)", "pattern")

	created, err := s.CreateContent(ctx, &CreateParams{
		Slug:    "binary-search-family",
		Title:   "Binary Search family",
		Body:    "Cross-variant notes on binary search.",
		Excerpt: "Common invariants across rotated / answer-space variants.",
		Type:    TypeArticle,
		Status:  StatusDraft,
		Concepts: []ConceptRef{
			{ID: cid1, Relevance: "primary"},
			{ID: cid2, Relevance: "secondary"},
		},
	})
	if err != nil {
		t.Fatalf("CreateContent(article + concept_ids) error: %v", err)
	}

	// Verify both rows in content_concepts.
	got := contentConceptIDs(t, testPool, created.ID)
	want := []uuid.UUID{cid1, cid2}
	// Sort both slices so ordering differences don't fail the test.
	sortUUIDs := cmpopts.SortSlices(func(a, b uuid.UUID) bool { return a.String() < b.String() })
	if diff := cmp.Diff(want, got, sortUUIDs); diff != "" {
		t.Errorf("content_concepts for %s mismatch (-want +got):\n%s", created.ID, diff)
	}
}

func TestStore_Contents_Pagination(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create 5 published contents.
	for i := range 5 {
		slug := "page-" + string(rune('a'+i))
		params := &CreateParams{
			Slug:    slug,
			Title:   "Title " + slug,
			Body:    "body",
			Excerpt: "excerpt",
			Type:    TypeArticle,
			Status:  StatusDraft,
		}
		created, err := s.CreateContent(ctx, params)
		if err != nil {
			t.Fatalf("CreateContent(%q) error: %v", slug, err)
		}
		// Publish so Contents (which queries published) can see them.
		if _, err := s.PublishContent(ctx, created.ID); err != nil {
			t.Fatalf("PublishContent(%s) error: %v", created.ID, err)
		}
	}

	tests := []struct {
		name      string
		filter    Filter
		wantLen   int
		wantTotal int
	}{
		{
			name:      "first page",
			filter:    Filter{Page: 1, PerPage: 2},
			wantLen:   2,
			wantTotal: 5,
		},
		{
			name:      "second page",
			filter:    Filter{Page: 2, PerPage: 2},
			wantLen:   2,
			wantTotal: 5,
		},
		{
			name:      "last page partial",
			filter:    Filter{Page: 3, PerPage: 2},
			wantLen:   1,
			wantTotal: 5,
		},
		{
			name:      "all on one page",
			filter:    Filter{Page: 1, PerPage: 100},
			wantLen:   5,
			wantTotal: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contents, total, err := s.Contents(ctx, tt.filter)
			if err != nil {
				t.Fatalf("Contents(%+v) error: %v", tt.filter, err)
			}
			if len(contents) != tt.wantLen {
				t.Errorf("Contents(%+v) len = %d, want %d", tt.filter, len(contents), tt.wantLen)
			}
			if total != tt.wantTotal {
				t.Errorf("Contents(%+v) total = %d, want %d", tt.filter, total, tt.wantTotal)
			}
		})
	}
}

func TestStore_Contents_FilterByType(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create one article and one TIL, both published.
	for _, ct := range []struct {
		slug string
		typ  Type
	}{
		{"typed-article", TypeArticle},
		{"typed-til", TypeTIL},
	} {
		c, err := s.CreateContent(ctx, &CreateParams{
			Slug:    ct.slug,
			Title:   "Title",
			Body:    "body",
			Excerpt: "excerpt",
			Type:    ct.typ,
			Status:  StatusDraft,
		})
		if err != nil {
			t.Fatalf("CreateContent(%q) error: %v", ct.slug, err)
		}
		if _, err := s.PublishContent(ctx, c.ID); err != nil {
			t.Fatalf("PublishContent(%s) error: %v", c.ID, err)
		}
	}

	articleType := TypeArticle
	contents, total, err := s.Contents(ctx, Filter{Page: 1, PerPage: 100, Type: &articleType})
	if err != nil {
		t.Fatalf("Contents(type=article) error: %v", err)
	}
	if total != 1 {
		t.Errorf("Contents(type=article) total = %d, want 1", total)
	}
	if len(contents) != 1 {
		t.Errorf("Contents(type=article) len = %d, want 1", len(contents))
	}
}

func TestStore_UpdateContent(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	tp1 := seedTopic(t, testPool, "topic-a", "Topic A")
	tp2 := seedTopic(t, testPool, "topic-b", "Topic B")

	created, err := s.CreateContent(ctx, &CreateParams{
		Slug:           "update-me",
		Title:          "Original Title",
		Body:           "original body",
		Excerpt:        "original excerpt",
		Type:           TypeArticle,
		Status:         StatusDraft,
		TopicIDs:       []uuid.UUID{tp1.ID},
		ReadingTimeMin: 2,
	})
	if err != nil {
		t.Fatalf("CreateContent() error: %v", err)
	}

	newTitle := "Updated Title"
	newBody := "updated body"
	newExcerpt := "updated excerpt"
	newReadingTime := 10

	updated, err := s.UpdateContent(ctx, created.ID, &UpdateParams{
		Title:          &newTitle,
		Body:           &newBody,
		Excerpt:        &newExcerpt,
		TopicIDs:       []uuid.UUID{tp2.ID},
		ReadingTimeMin: &newReadingTime,
	})
	if err != nil {
		t.Fatalf("UpdateContent(%s) error: %v", created.ID, err)
	}

	if updated.Title != newTitle {
		t.Errorf("UpdateContent() title = %q, want %q", updated.Title, newTitle)
	}
	if updated.Body != newBody {
		t.Errorf("UpdateContent() body = %q, want %q", updated.Body, newBody)
	}
	if updated.Excerpt != newExcerpt {
		t.Errorf("UpdateContent() excerpt = %q, want %q", updated.Excerpt, newExcerpt)
	}
	if updated.ReadingTimeMin != newReadingTime {
		t.Errorf("UpdateContent() reading_time = %d, want %d", updated.ReadingTimeMin, newReadingTime)
	}

	// Verify topics were replaced: only tp2, not tp1.
	if len(updated.Topics) != 1 {
		t.Fatalf("UpdateContent() topics len = %d, want 1", len(updated.Topics))
	}
	if updated.Topics[0].ID != tp2.ID {
		t.Errorf("UpdateContent() topic ID = %s, want %s", updated.Topics[0].ID, tp2.ID)
	}
}

func TestStore_DeleteContent(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	created, err := s.CreateContent(ctx, &CreateParams{
		Slug:    "delete-me",
		Title:   "Delete Me",
		Body:    "body",
		Excerpt: "excerpt",
		Type:    TypeArticle,
		Status:  StatusDraft,
	})
	if err != nil {
		t.Fatalf("CreateContent() error: %v", err)
	}

	// Delete sets status to archived.
	if err := s.DeleteContent(ctx, created.ID); err != nil {
		t.Fatalf("DeleteContent(%s) error: %v", created.ID, err)
	}

	// Content should still be retrievable by ID (archived, not hard-deleted).
	got, err := s.Content(ctx, created.ID)
	if err != nil {
		t.Fatalf("Content(%s) after delete error: %v", created.ID, err)
	}
	if got.Status != StatusArchived {
		t.Errorf("Content(%s) after delete status = %q, want %q", created.ID, got.Status, StatusArchived)
	}
}

func TestStore_ContentBySlug(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	created, err := s.CreateContent(ctx, &CreateParams{
		Slug:           "find-by-slug",
		Title:          "Find By Slug",
		Body:           "body",
		Excerpt:        "excerpt",
		Type:           TypeEssay,
		Status:         StatusDraft,
		ReadingTimeMin: 3,
	})
	if err != nil {
		t.Fatalf("CreateContent() error: %v", err)
	}

	tests := []struct {
		name    string
		slug    string
		wantErr error
	}{
		{name: "existing slug", slug: "find-by-slug", wantErr: nil},
		{name: "missing slug", slug: "nonexistent", wantErr: ErrNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.ContentBySlug(ctx, tt.slug)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Fatalf("ContentBySlug(%q) error = %v, want %v", tt.slug, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ContentBySlug(%q) unexpected error: %v", tt.slug, err)
			}
			if got.ID != created.ID {
				t.Errorf("ContentBySlug(%q) ID = %s, want %s", tt.slug, got.ID, created.ID)
			}
			if got.Slug != tt.slug {
				t.Errorf("ContentBySlug(%q) slug = %q, want %q", tt.slug, got.Slug, tt.slug)
			}
		})
	}
}

func TestStore_Content_NotFound(t *testing.T) {
	s := setup(t)

	_, err := s.Content(t.Context(), uuid.New())
	if err != ErrNotFound {
		t.Fatalf("Content(missing ID) = %v, want ErrNotFound", err)
	}
}

func TestStore_PublishContent(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	created, err := s.CreateContent(ctx, &CreateParams{
		Slug:    "publish-me",
		Title:   "Publish Me",
		Body:    "body",
		Excerpt: "excerpt",
		Type:    TypeArticle,
		Status:  StatusDraft,
	})
	if err != nil {
		t.Fatalf("CreateContent() error: %v", err)
	}

	if created.Status != StatusDraft {
		t.Fatalf("CreateContent() status = %q, want %q", created.Status, StatusDraft)
	}
	if created.PublishedAt != nil {
		t.Fatal("CreateContent() published_at should be nil for draft")
	}

	published, err := s.PublishContent(ctx, created.ID)
	if err != nil {
		t.Fatalf("PublishContent(%s) error: %v", created.ID, err)
	}

	if published.Status != StatusPublished {
		t.Errorf("PublishContent(%s) status = %q, want %q", created.ID, published.Status, StatusPublished)
	}
	if published.PublishedAt == nil {
		t.Error("PublishContent() published_at should not be nil")
	}
}

func TestStore_PublishContent_NotFound(t *testing.T) {
	s := setup(t)

	_, err := s.PublishContent(t.Context(), uuid.New())
	if err != ErrNotFound {
		t.Fatalf("PublishContent(missing ID) = %v, want ErrNotFound", err)
	}
}

func TestStore_UpdateContent_NotFound(t *testing.T) {
	s := setup(t)

	newTitle := "whatever"
	_, err := s.UpdateContent(t.Context(), uuid.New(), &UpdateParams{
		Title: &newTitle,
	})
	if err != ErrNotFound {
		t.Fatalf("UpdateContent(missing ID) = %v, want ErrNotFound", err)
	}
}
