//go:build integration

package content

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/blog-backend/internal/testdb"
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
	if err := testdb.TruncateCtx(t.Context(), testPool, "content_topics", "contents", "topics"); err != nil {
		t.Fatal(err)
	}
	return NewStore(testPool)
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
		Slug:        "test-article",
		Title:       "Test Article",
		Body:        "This is the body of the test article.",
		Excerpt:     "A short excerpt.",
		Type:        TypeArticle,
		Status:      StatusDraft,
		Tags:        []string{"go", "testing"},
		TopicIDs:    []uuid.UUID{tp.ID},
		ReviewLevel: ReviewStandard,
		ReadingTime: 5,
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

	want := &Content{
		ID:          created.ID,
		Slug:        "test-article",
		Title:       "Test Article",
		Body:        "This is the body of the test article.",
		Excerpt:     "A short excerpt.",
		Type:        TypeArticle,
		Status:      StatusDraft,
		Tags:        []string{"go", "testing"},
		Topics:      []TopicRef{{ID: tp.ID, Slug: "golang", Name: "Go Language"}},
		ReviewLevel: ReviewStandard,
		Visibility:  "public",
		ReadingTime: 5,
		CreatedAt:   created.CreatedAt,
		UpdatedAt:   created.UpdatedAt,
	}

	if diff := cmp.Diff(want, got, cmpContentOpts); diff != "" {
		t.Errorf("Content(%s) mismatch (-want +got):\n%s", created.ID, diff)
	}
}

func TestStore_CreateContent_DuplicateSlug(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	params := &CreateParams{
		Slug:        "duplicate-slug",
		Title:       "First",
		Body:        "body",
		Excerpt:     "excerpt",
		Type:        TypeTIL,
		Status:      StatusDraft,
		Tags:        []string{},
		ReviewLevel: ReviewAuto,
	}

	if _, err := s.CreateContent(ctx, params); err != nil {
		t.Fatalf("CreateContent() first call error: %v", err)
	}

	// Second create with same slug must return ErrConflict.
	_, err := s.CreateContent(ctx, params)
	if err != ErrConflict {
		t.Fatalf("CreateContent(duplicate slug) = %v, want ErrConflict", err)
	}
}

func TestStore_Contents_Pagination(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create 5 published contents.
	for i := range 5 {
		slug := "page-" + string(rune('a'+i))
		params := &CreateParams{
			Slug:        slug,
			Title:       "Title " + slug,
			Body:        "body",
			Excerpt:     "excerpt",
			Type:        TypeArticle,
			Status:      StatusDraft,
			Tags:        []string{},
			ReviewLevel: ReviewAuto,
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
			Slug:        ct.slug,
			Title:       "Title",
			Body:        "body",
			Excerpt:     "excerpt",
			Type:        ct.typ,
			Status:      StatusDraft,
			Tags:        []string{},
			ReviewLevel: ReviewAuto,
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
		Slug:        "update-me",
		Title:       "Original Title",
		Body:        "original body",
		Excerpt:     "original excerpt",
		Type:        TypeNote,
		Status:      StatusDraft,
		Tags:        []string{"old"},
		TopicIDs:    []uuid.UUID{tp1.ID},
		ReviewLevel: ReviewLight,
		ReadingTime: 2,
	})
	if err != nil {
		t.Fatalf("CreateContent() error: %v", err)
	}

	newTitle := "Updated Title"
	newBody := "updated body"
	newExcerpt := "updated excerpt"
	newReadingTime := 10

	updated, err := s.UpdateContent(ctx, created.ID, &UpdateParams{
		Title:       &newTitle,
		Body:        &newBody,
		Excerpt:     &newExcerpt,
		Tags:        []string{"new", "tags"},
		TopicIDs:    []uuid.UUID{tp2.ID},
		ReadingTime: &newReadingTime,
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
	if updated.ReadingTime != newReadingTime {
		t.Errorf("UpdateContent() reading_time = %d, want %d", updated.ReadingTime, newReadingTime)
	}

	// Verify topics were replaced: only tp2, not tp1.
	if len(updated.Topics) != 1 {
		t.Fatalf("UpdateContent() topics len = %d, want 1", len(updated.Topics))
	}
	if updated.Topics[0].ID != tp2.ID {
		t.Errorf("UpdateContent() topic ID = %s, want %s", updated.Topics[0].ID, tp2.ID)
	}

	// Verify tags were replaced.
	wantTags := []string{"new", "tags"}
	if diff := cmp.Diff(wantTags, updated.Tags, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
		t.Errorf("UpdateContent() tags mismatch (-want +got):\n%s", diff)
	}
}

func TestStore_DeleteContent(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	created, err := s.CreateContent(ctx, &CreateParams{
		Slug:        "delete-me",
		Title:       "Delete Me",
		Body:        "body",
		Excerpt:     "excerpt",
		Type:        TypeNote,
		Status:      StatusDraft,
		Tags:        []string{},
		ReviewLevel: ReviewAuto,
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
		Slug:        "find-by-slug",
		Title:       "Find By Slug",
		Body:        "body",
		Excerpt:     "excerpt",
		Type:        TypeEssay,
		Status:      StatusDraft,
		Tags:        []string{"essay"},
		ReviewLevel: ReviewStandard,
		ReadingTime: 3,
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
		Slug:        "publish-me",
		Title:       "Publish Me",
		Body:        "body",
		Excerpt:     "excerpt",
		Type:        TypeArticle,
		Status:      StatusDraft,
		Tags:        []string{},
		ReviewLevel: ReviewAuto,
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
