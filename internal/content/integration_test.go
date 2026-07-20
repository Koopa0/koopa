// Copyright 2026 Koopa. All rights reserved.

//go:build integration

package content

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/api"
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

func setup(t *testing.T) *Store {
	t.Helper()
	// Junction + dependent tables first, then contents, then the topic catalog.
	if err := testdb.TruncateCtx(t.Context(), testPool,
		"content_topics", "contents", "topics"); err != nil {
		t.Fatal(err)
	}
	// Seed the 'system' agent so the contents/learning_attempts AFTER
	// triggers (which INSERT into activity_events with actor=current_actor()
	// and fall back to 'system' when koopa.actor is not SET LOCAL) do not
	// hit activity_events_actor_fkey. Seed 'human' too so fixtures that
	// need an explicit caller identity for created_by (concepts, learning
	// targets) can FK against it — this mirrors the admin HTTP path's
	// caller-identity convention used in internal/mcp's integration tests.
	// In production cmd/mcp wires this via agent.SyncToTable(BuiltinAgents());
	// integration tests don't boot the MCP server so the seed is done directly.
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO agents (name, display_name, platform)
		 VALUES ('human', 'Human', 'human')
		 ON CONFLICT (name) DO NOTHING`); err != nil {
		t.Fatalf("seeding agents: %v", err)
	}
	return NewStore(testPool)
}

// seedLearningTarget helper has been removed alongside the
// 1:1 learning_targets.content_id FK. Target writeups now attach via the
// learning_target_notes junction (note package); integration coverage
// lives in the note/learning packages' own tests.

// cmpContentOpts are reusable cmp options for Content comparison.
// Timestamps are compared with 1-second tolerance, and Topics slice ordering is ignored.
var cmpContentOpts = cmp.Options{
	cmpopts.EquateApproxTime(time.Second),
	cmpopts.SortSlices(func(a, b TopicRef) bool { return a.Slug < b.Slug }),
}

// createContentTx runs CreateContent inside a committed pgx.Tx, mirroring the
// production admin path where api.ActorMiddleware opens the tx and the handler
// binds the store via WithTx. CreateContent with junction rows (TopicIDs)
// rejects a pool-backed store with ErrNotTransactional — the write fans out to
// contents + content_topics and must commit as a unit — so the integration
// suite must drive it through a transaction just like the real caller does.
// Same shape as TestStore_CreateContent_DuplicateSlug_InTx.
func createContentTx(t *testing.T, ctx context.Context, p *CreateParams) *Content {
	t.Helper()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	created, err := NewStore(tx).CreateContent(ctx, p)
	if err != nil {
		t.Fatalf("CreateContent() error: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit tx: %v", err)
	}
	return created
}

// updateContentTx runs UpdateContent inside a committed pgx.Tx for the same
// reason as createContentTx: topic/concept junction replacement is a multi-row
// write that requires a transactional store.
func updateContentTx(t *testing.T, ctx context.Context, id uuid.UUID, p *UpdateParams) *Content {
	t.Helper()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	updated, err := NewStore(tx).UpdateContent(ctx, id, p)
	if err != nil {
		t.Fatalf("UpdateContent(%s) error: %v", id, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit tx: %v", err)
	}
	return updated
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

	// TopicIDs makes this a multi-row (contents + content_topics) write, so
	// CreateContent must run through a transactional store — drive it the way
	// api.ActorMiddleware does in production.
	created := createContentTx(t, ctx, params)

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
	want := &Content{
		ID:             created.ID,
		Slug:           "test-article",
		Title:          "Test Article",
		Body:           "This is the body of the test article.",
		Excerpt:        "A short excerpt.",
		Type:           TypeArticle,
		Status:         StatusDraft,
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

// TestStore_CreateContent_MultipleTopics exercises the batch topic-insert
// path (InsertContentTopics, UNNEST-based) with more than one topic — the
// existing single-topic tests never call it with a real array, so a bug
// where only the first element of a multi-topic slice were inserted (or
// a length-mismatch edge case) would not otherwise be caught.
func TestStore_CreateContent_MultipleTopics(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	tp1 := seedTopic(t, testPool, "go", "Go")
	tp2 := seedTopic(t, testPool, "rust", "Rust")
	tp3 := seedTopic(t, testPool, "postgres", "PostgreSQL")

	created := createContentTx(t, ctx, &CreateParams{
		Slug:           "multi-topic-article",
		Title:          "Multi Topic Article",
		Body:           "body",
		Excerpt:        "excerpt",
		Type:           TypeArticle,
		Status:         StatusDraft,
		TopicIDs:       []uuid.UUID{tp1.ID, tp2.ID, tp3.ID},
		ReadingTimeMin: 3,
	})

	got, err := s.Content(ctx, created.ID)
	if err != nil {
		t.Fatalf("Content(%s) error: %v", created.ID, err)
	}
	wantTopics := []TopicRef{
		{ID: tp1.ID, Slug: "go", Name: "Go"},
		{ID: tp2.ID, Slug: "rust", Name: "Rust"},
		{ID: tp3.ID, Slug: "postgres", Name: "PostgreSQL"},
	}
	sortTopics := cmpopts.SortSlices(func(a, b TopicRef) bool { return a.ID.String() < b.ID.String() })
	if diff := cmp.Diff(wantTopics, got.Topics, sortTopics); diff != "" {
		t.Errorf("CreateContent() topics mismatch (-want +got):\n%s", diff)
	}

	// Replace with a different, smaller topic set — the DELETE-then-batch-
	// INSERT path in UpdateContent must fully swap, not merge.
	updated := updateContentTx(t, ctx, created.ID, &UpdateParams{
		TopicIDs: []uuid.UUID{tp2.ID},
	})
	wantAfterUpdate := []TopicRef{{ID: tp2.ID, Slug: "rust", Name: "Rust"}}
	if diff := cmp.Diff(wantAfterUpdate, updated.Topics, sortTopics); diff != "" {
		t.Errorf("UpdateContent() topics mismatch (-want +got):\n%s", diff)
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
		bindTestSource(t, created.ID, slug)
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
		bindTestSource(t, c.ID, ct.slug)
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
	// setup truncates and seeds agents; the create/update both run through
	// tx helpers, so the returned pool-backed store is not needed here.
	setup(t)
	ctx := t.Context()

	tp1 := seedTopic(t, testPool, "topic-a", "Topic A")
	tp2 := seedTopic(t, testPool, "topic-b", "Topic B")

	// Both create and update attach a content_topics junction row, so each is
	// a multi-row write that must run through a transactional store.
	created := createContentTx(t, ctx, &CreateParams{
		Slug:           "update-me",
		Title:          "Original Title",
		Body:           "original body",
		Excerpt:        "original excerpt",
		Type:           TypeArticle,
		Status:         StatusDraft,
		TopicIDs:       []uuid.UUID{tp1.ID},
		ReadingTimeMin: 2,
	})

	newTitle := "Updated Title"
	newBody := "updated body"
	newExcerpt := "updated excerpt"
	newReadingTime := 10

	updated := updateContentTx(t, ctx, created.ID, &UpdateParams{
		Title:          &newTitle,
		Body:           &newBody,
		Excerpt:        &newExcerpt,
		TopicIDs:       []uuid.UUID{tp2.ID},
		ReadingTimeMin: &newReadingTime,
	})

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

// TestStore_UpdateContent_PublishedSnapshotIsImmutable locks the authoring
// boundary: Vault is the source of a published revision, so the generic admin
// update path must not silently rewrite the publication snapshot in Koopa.
// Visibility remains a separate operational control.
func TestStore_UpdateContent_PublishedSnapshotIsImmutable(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	id := createDraftContent(t, s, ctx, "published-snapshot")
	published, err := s.Publish(ctx, id)
	if err != nil {
		t.Fatalf("Publish() error: %v", err)
	}

	newTitle := "Edited only in Koopa"
	newBody := "this edit did not originate from a new Vault snapshot"
	notPublic := false
	_, err = s.UpdateContent(ctx, id, &UpdateParams{
		Title:    &newTitle,
		Body:     &newBody,
		IsPublic: &notPublic,
	})
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("UpdateContent(published) = %v, want ErrInvalidState", err)
	}

	got, err := s.Content(ctx, id)
	if err != nil {
		t.Fatalf("Content() after rejected update: %v", err)
	}
	if diff := cmp.Diff(published, got, cmpContentOpts); diff != "" {
		t.Errorf("published snapshot changed after rejected update (-want +got):\n%s", diff)
	}
}

// TestStore_PublishRequiresSourceSnapshot locks the D4 promotion boundary:
// an unbound Koopa row is not a publishable Vault snapshot. The failed
// transition must leave state, visibility, and published_at untouched.
func TestStore_PublishRequiresSourceSnapshot(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	unbound, err := s.CreateContent(ctx, &CreateParams{
		Slug: "unbound-publish", Title: "Unbound", Body: "body", Excerpt: "excerpt",
		Type: TypeArticle, Status: StatusDraft,
	})
	if err != nil {
		t.Fatalf("CreateContent(unbound): %v", err)
	}
	id := unbound.ID
	_, err = s.Publish(ctx, id)
	if err == nil || !strings.Contains(err.Error(), "source snapshot required") {
		t.Fatalf("Publish(unbound draft) = %v, want source snapshot required", err)
	}
	_, err = s.SubmitContentForReview(ctx, id)
	if !errors.Is(err, ErrSourceRequired) {
		t.Fatalf("SubmitContentForReview(unbound draft) = %v, want ErrSourceRequired", err)
	}
	review := StatusReview
	_, err = s.UpdateContent(ctx, id, &UpdateParams{Status: &review})
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("UpdateContent(unbound draft, status=review) = %v, want ErrInvalidState", err)
	}

	got, err := s.Content(ctx, id)
	if err != nil {
		t.Fatalf("Content() after rejected publish: %v", err)
	}
	if got.Status != StatusDraft || got.IsPublic || got.PublishedAt != nil {
		t.Fatalf("rejected publish mutated row: status=%q public=%t published_at=%v", got.Status, got.IsPublic, got.PublishedAt)
	}
}

// TestStore_WithdrawalLifecycle drives the production handlers through
// ActorMiddleware. It deliberately warms both syndication responses before
// withdrawal: a TTL-only cache would keep serving the removed snapshot and
// make this test fail even if the database transition itself were correct.
func TestStore_WithdrawalLifecycle(t *testing.T) {
	s := setup(t)
	ctx := t.Context()
	id := createDraftContent(t, s, ctx, "withdrawal-lifecycle")
	published, err := s.Publish(ctx, id)
	if err != nil {
		t.Fatalf("Publish() error: %v", err)
	}
	if published.PublishedAt == nil {
		t.Fatal("Publish() published_at is nil")
	}
	originalPublishedAt := *published.PublishedAt

	h := NewHandler(s, "https://example.test", slog.Default())
	for _, endpoint := range []struct {
		name string
		call http.HandlerFunc
	}{
		{name: "rss", call: h.RSS},
		{name: "sitemap", call: h.Sitemap},
	} {
		rec := httptest.NewRecorder()
		endpoint.call(rec, httptest.NewRequest(http.MethodGet, "/api/feed/"+endpoint.name, http.NoBody))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "withdrawal-lifecycle") {
			t.Fatalf("warm %s = status %d body %q, want published slug", endpoint.name, rec.Code, rec.Body.String())
		}
	}

	actions := requireWithdrawalHandler(t, h)
	withdraw := api.ActorMiddleware(testPool, "human", slog.Default())(http.HandlerFunc(actions.Withdraw))
	withdrawReq := httptest.NewRequest(http.MethodPost,
		"/api/admin/knowledge/content/"+id.String()+"/withdraw",
		strings.NewReader(`{"reason":"  Contains private contact details.  "}`))
	withdrawReq.Header.Set("Content-Type", "application/json")
	withdrawReq.SetPathValue("id", id.String())
	withdrawRec := httptest.NewRecorder()
	withdraw.ServeHTTP(withdrawRec, withdrawReq)
	if withdrawRec.Code != http.StatusOK {
		t.Fatalf("Withdraw() status = %d, want 200 (body=%s)", withdrawRec.Code, withdrawRec.Body.String())
	}

	withdrawn, err := s.Content(ctx, id)
	if err != nil {
		t.Fatalf("Content() after withdraw: %v", err)
	}
	if withdrawn.Status != StatusPublished || withdrawn.IsPublic {
		t.Fatalf("withdrawn state = status %q public=%t, want published/private", withdrawn.Status, withdrawn.IsPublic)
	}
	if withdrawn.WithdrawnAt == nil || withdrawn.WithdrawalReason == nil || *withdrawn.WithdrawalReason != "Contains private contact details." {
		t.Fatalf("withdrawal metadata = at %v reason %v, want timestamp and trimmed reason", withdrawn.WithdrawnAt, withdrawn.WithdrawalReason)
	}
	if withdrawn.PublishedAt == nil || !withdrawn.PublishedAt.Equal(originalPublishedAt) {
		t.Fatalf("published_at after withdraw = %v, want %v", withdrawn.PublishedAt, originalPublishedAt)
	}

	assertNotPublic := func(name string, call http.HandlerFunc, req *http.Request) {
		t.Helper()
		rec := httptest.NewRecorder()
		call(rec, req)
		if strings.Contains(rec.Body.String(), "withdrawal-lifecycle") || strings.Contains(rec.Body.String(), "Contains private contact details") {
			t.Fatalf("%s leaked withdrawn content: %s", name, rec.Body.String())
		}
	}
	detailReq := httptest.NewRequest(http.MethodGet, "/api/contents/withdrawal-lifecycle", http.NoBody)
	detailReq.SetPathValue("slug", "withdrawal-lifecycle")
	detailRec := httptest.NewRecorder()
	h.PublicBySlug(detailRec, detailReq)
	if detailRec.Code != http.StatusNotFound {
		t.Fatalf("public detail after withdraw = %d, want 404 (body=%s)", detailRec.Code, detailRec.Body.String())
	}
	assertNotPublic("list", h.PublicList, httptest.NewRequest(http.MethodGet, "/api/contents", http.NoBody))
	assertNotPublic("rss", h.RSS, httptest.NewRequest(http.MethodGet, "/api/feed/rss", http.NoBody))
	assertNotPublic("sitemap", h.Sitemap, httptest.NewRequest(http.MethodGet, "/api/feed/sitemap", http.NoBody))

	var withdrawEventID uuid.UUID
	var withdrawActor, withdrawKind string
	var withdrawPayload []byte
	err = testPool.QueryRow(ctx, `
		SELECT id, actor, change_kind, payload
		FROM activity_events
		WHERE entity_type = 'content' AND entity_id = $1
		  AND payload->>'transition' = 'withdrawn'`, id).
		Scan(&withdrawEventID, &withdrawActor, &withdrawKind, &withdrawPayload)
	if err != nil {
		t.Fatalf("query withdrawal receipt: %v", err)
	}
	if withdrawEventID == uuid.Nil || withdrawActor != "human" || withdrawKind != "state_changed" {
		t.Fatalf("withdraw receipt = id %s actor %q kind %q", withdrawEventID, withdrawActor, withdrawKind)
	}
	var withdrawMeta map[string]any
	if err := json.Unmarshal(withdrawPayload, &withdrawMeta); err != nil {
		t.Fatalf("decode withdrawal receipt: %v", err)
	}
	for key, want := range map[string]string{
		"from": "public", "to": "withdrawn", "reason": "Contains private contact details.",
	} {
		if got := withdrawMeta[key]; got != want {
			t.Errorf("withdraw payload[%q] = %v, want %q", key, got, want)
		}
	}

	window, err := s.PublishedInWindow(ctx, originalPublishedAt.Add(-time.Minute), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("PublishedInWindow() after withdraw: %v", err)
	}
	if len(window) != 1 || window[0].Title != published.Title {
		t.Fatalf("PublishedInWindow() after withdraw = %+v, want original publication", window)
	}

	restore := api.ActorMiddleware(testPool, "human", slog.Default())(http.HandlerFunc(actions.Restore))
	restoreReq := httptest.NewRequest(http.MethodPost,
		"/api/admin/knowledge/content/"+id.String()+"/restore", http.NoBody)
	restoreReq.SetPathValue("id", id.String())
	restoreRec := httptest.NewRecorder()
	restore.ServeHTTP(restoreRec, restoreReq)
	if restoreRec.Code != http.StatusOK {
		t.Fatalf("Restore() status = %d, want 200 (body=%s)", restoreRec.Code, restoreRec.Body.String())
	}

	restored, err := s.Content(ctx, id)
	if err != nil {
		t.Fatalf("Content() after restore: %v", err)
	}
	if restored.Status != StatusPublished || !restored.IsPublic || restored.WithdrawnAt != nil || restored.WithdrawalReason != nil {
		t.Fatalf("restored state = status %q public=%t at=%v reason=%v", restored.Status, restored.IsPublic, restored.WithdrawnAt, restored.WithdrawalReason)
	}
	if restored.PublishedAt == nil || !restored.PublishedAt.Equal(originalPublishedAt) {
		t.Fatalf("published_at after restore = %v, want %v", restored.PublishedAt, originalPublishedAt)
	}

	for _, endpoint := range []struct {
		name string
		call http.HandlerFunc
	}{
		{name: "rss", call: h.RSS},
		{name: "sitemap", call: h.Sitemap},
	} {
		rec := httptest.NewRecorder()
		endpoint.call(rec, httptest.NewRequest(http.MethodGet, "/api/feed/"+endpoint.name, http.NoBody))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "withdrawal-lifecycle") {
			t.Fatalf("%s after restore = status %d body %q, want restored slug", endpoint.name, rec.Code, rec.Body.String())
		}
	}

	var restorePayload []byte
	err = testPool.QueryRow(ctx, `
		SELECT payload
		FROM activity_events
		WHERE entity_type = 'content' AND entity_id = $1
		  AND payload->>'transition' = 'restored'`, id).Scan(&restorePayload)
	if err != nil {
		t.Fatalf("query restore receipt: %v", err)
	}
	var restoreCount int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM activity_events
		WHERE entity_type = 'content' AND entity_id = $1
		  AND payload->>'transition' = 'restored'`, id).Scan(&restoreCount); err != nil {
		t.Fatalf("count restore receipts: %v", err)
	}
	if restoreCount != 1 {
		t.Fatalf("restore receipt count = %d, want 1", restoreCount)
	}
	var restoreMeta map[string]any
	if err := json.Unmarshal(restorePayload, &restoreMeta); err != nil {
		t.Fatalf("decode restore receipt: %v", err)
	}
	for key, want := range map[string]string{
		"from": "withdrawn", "to": "public", "reason": "Contains private contact details.",
	} {
		if got := restoreMeta[key]; got != want {
			t.Errorf("restore payload[%q] = %v, want %q", key, got, want)
		}
	}
}

func TestSchema_ContentWithdrawalConstraints(t *testing.T) {
	s := setup(t)
	ctx := t.Context()
	id := createDraftContent(t, s, ctx, "withdrawal-constraints")
	if _, err := s.Publish(ctx, id); err != nil {
		t.Fatalf("Publish() error: %v", err)
	}

	if _, err := testPool.Exec(ctx, `
		UPDATE contents
		SET is_public = false,
		    withdrawn_at = now(),
		    withdrawal_reason = 'Valid migration-level withdrawal'
		WHERE id = $1`, id); err != nil {
		t.Fatalf("valid withdrawal tuple rejected: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE contents
		SET is_public = true, withdrawn_at = NULL, withdrawal_reason = NULL
		WHERE id = $1`, id); err != nil {
		t.Fatalf("valid restore tuple rejected: %v", err)
	}

	invalid := []struct {
		name string
		sql  string
	}{
		{name: "missing reason", sql: `UPDATE contents SET is_public=false, withdrawn_at=now(), withdrawal_reason=NULL WHERE id=$1`},
		{name: "blank reason", sql: `UPDATE contents SET is_public=false, withdrawn_at=now(), withdrawal_reason='   ' WHERE id=$1`},
		{name: "missing timestamp", sql: `UPDATE contents SET is_public=false, withdrawn_at=NULL, withdrawal_reason='reason' WHERE id=$1`},
		{name: "metadata while public", sql: `UPDATE contents SET is_public=true, withdrawn_at=now(), withdrawal_reason='reason' WHERE id=$1`},
		{name: "oversized reason", sql: `UPDATE contents SET is_public=false, withdrawn_at=now(), withdrawal_reason=repeat('x', 501) WHERE id=$1`},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := testPool.Exec(ctx, tc.sql, id); err == nil {
				t.Fatalf("invalid withdrawal tuple was accepted")
			}
		})
	}
}

func TestStore_WithdrawalGuards(t *testing.T) {
	s := setup(t)
	ctx := t.Context()
	actions := requireWithdrawalStore(t, s)

	draft, err := s.CreateContent(ctx, &CreateParams{
		Slug: "withdraw-draft", Title: "Draft", Body: "body", Excerpt: "excerpt",
		Type: TypeArticle, Status: StatusDraft,
	})
	if err != nil {
		t.Fatalf("CreateContent() error: %v", err)
	}
	if _, err := actions.Withdraw(ctx, draft.ID, "not published"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Withdraw(draft) = %v, want ErrInvalidState", err)
	}
	if _, err := actions.Withdraw(ctx, uuid.New(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Withdraw(missing) = %v, want ErrNotFound", err)
	}
	if _, err := actions.Restore(ctx, draft.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Restore(draft) = %v, want ErrInvalidState", err)
	}

	publishedID := createDraftContent(t, s, ctx, "withdraw-once")
	if _, err := s.Publish(ctx, publishedID); err != nil {
		t.Fatalf("Publish() error: %v", err)
	}
	if _, err := actions.Withdraw(ctx, publishedID, "first reason"); err != nil {
		t.Fatalf("Withdraw() error: %v", err)
	}
	if _, err := actions.Withdraw(ctx, publishedID, "replacement reason"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("repeated Withdraw() = %v, want ErrInvalidState", err)
	}
	if _, err := actions.Restore(ctx, publishedID); err != nil {
		t.Fatalf("Restore() error: %v", err)
	}
	if _, err := actions.Restore(ctx, publishedID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("repeated Restore() = %v, want ErrInvalidState", err)
	}

	var transitionCount int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM activity_events
		WHERE entity_type='content' AND entity_id=$1
		  AND payload->>'transition' IN ('withdrawn','restored')`, publishedID).Scan(&transitionCount); err != nil {
		t.Fatalf("count transition receipts: %v", err)
	}
	if transitionCount != 2 {
		t.Fatalf("transition receipt count = %d, want 2", transitionCount)
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
				if !errors.Is(err, tt.wantErr) {
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
	if !errors.Is(err, ErrNotFound) {
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
	bindTestSource(t, created.ID, "publish-me")

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
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("PublishContent(missing ID) = %v, want ErrNotFound", err)
	}
}

// createDraftContent inserts a draft content row and returns its id. Helper
// for the Publish state-guard tests, which need rows in a known
// source state before exercising the transition.
func createDraftContent(t *testing.T, s *Store, ctx context.Context, slug string) uuid.UUID {
	t.Helper()
	c, err := s.CreateContent(ctx, &CreateParams{
		Slug:    slug,
		Title:   "Title",
		Body:    "body",
		Excerpt: "excerpt",
		Type:    TypeArticle,
		Status:  StatusDraft,
	})
	if err != nil {
		t.Fatalf("CreateContent(%q) error: %v", slug, err)
	}
	bindTestSource(t, c.ID, slug)
	return c.ID
}

func bindTestSource(t *testing.T, id uuid.UUID, slug string) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`UPDATE contents SET source_vault_path = $1, source_git_blob_sha = $2 WHERE id = $3`,
		"Writing/articles/"+slug+".md",
		"0123456789abcdef0123456789abcdef01234567",
		id,
	); err != nil {
		t.Fatalf("binding test source for %s: %v", id, err)
	}
}

// TestStore_Publish exercises the owner's publish gate: a draft (the owner's
// own finished work) or a review row (an agent proposal) is promoted to
// published; an archived row is rejected with ErrInvalidState. This is the guard
// behind the HTTP admin publish handler (publish is admin-only; agents reach
// review via propose_content).
func TestStore_Publish(t *testing.T) {
	tests := []struct {
		name       string
		setupState func(t *testing.T, s *Store, ctx context.Context) uuid.UUID
		wantStatus Status
		wantErr    error
	}{
		{
			name: "review transitions to published",
			setupState: func(t *testing.T, s *Store, ctx context.Context) uuid.UUID {
				id := createDraftContent(t, s, ctx, "pfr-review")
				if _, err := s.SubmitContentForReview(ctx, id); err != nil {
					t.Fatalf("SubmitContentForReview() error: %v", err)
				}
				return id
			},
			wantStatus: StatusPublished,
		},
		{
			name: "draft transitions to published",
			setupState: func(t *testing.T, s *Store, ctx context.Context) uuid.UUID {
				return createDraftContent(t, s, ctx, "pfr-draft")
			},
			wantStatus: StatusPublished,
		},
		{
			name: "archived is rejected",
			setupState: func(t *testing.T, s *Store, ctx context.Context) uuid.UUID {
				id := createDraftContent(t, s, ctx, "pfr-archived")
				if _, err := s.ArchiveContentReturning(ctx, id); err != nil {
					t.Fatalf("ArchiveContentReturning() error: %v", err)
				}
				return id
			},
			wantErr: ErrInvalidState,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := setup(t)
			ctx := t.Context()
			id := tt.setupState(t, s, ctx)

			got, err := s.Publish(ctx, id)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Publish() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Publish() unexpected error: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("Publish() status = %q, want %q", got.Status, tt.wantStatus)
			}
			if got.PublishedAt == nil {
				t.Error("Publish() published_at should not be nil after publish")
			}
		})
	}
}

// TestStore_Publish_Idempotent proves Policy B's published → published
// branch is a true no-op: a second publish succeeds without re-mutating the row
// (published_at is unchanged), so no spurious second 'published' audit event.
func TestStore_Publish_Idempotent(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	id := createDraftContent(t, s, ctx, "pfr-idempotent")
	if _, err := s.SubmitContentForReview(ctx, id); err != nil {
		t.Fatalf("SubmitContentForReview() error: %v", err)
	}

	first, err := s.Publish(ctx, id)
	if err != nil {
		t.Fatalf("Publish() first call error: %v", err)
	}
	second, err := s.Publish(ctx, id)
	if err != nil {
		t.Fatalf("Publish() second call (idempotent) error: %v", err)
	}

	if second.Status != StatusPublished {
		t.Errorf("Publish() idempotent status = %q, want %q", second.Status, StatusPublished)
	}
	if first.PublishedAt == nil || second.PublishedAt == nil {
		t.Fatal("Publish() published_at should be set after publish")
	}
	if !first.PublishedAt.Equal(*second.PublishedAt) {
		t.Errorf("Publish() idempotent published_at changed: first=%v second=%v", first.PublishedAt, second.PublishedAt)
	}
}

// TestStore_Publish_NotFound verifies a missing id surfaces as
// ErrNotFound (mapped to 404 / not-found at the call boundaries).
func TestStore_Publish_NotFound(t *testing.T) {
	s := setup(t)

	_, err := s.Publish(t.Context(), uuid.New())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Publish(missing ID) = %v, want ErrNotFound", err)
	}
}

func TestStore_UpdateContent_NotFound(t *testing.T) {
	s := setup(t)

	newTitle := "whatever"
	_, err := s.UpdateContent(t.Context(), uuid.New(), &UpdateParams{
		Title: &newTitle,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateContent(missing ID) = %v, want ErrNotFound", err)
	}
}

// TestStore_Content_SurfacesReviewNote proves the admin detail read (the Content
// store method backing ContentByID) returns the owner's review_note after a
// send-back, so reopening a changes_requested item in admin shows the note. The
// MCP list_content readback (ContentsByCreator) already surfaced it; this closes
// the gap where the detail read selected every column EXCEPT review_note.
func TestStore_Content_SurfacesReviewNote(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	id := createDraftContent(t, s, ctx, "review-note-detail")
	if _, err := s.SubmitContentForReview(ctx, id); err != nil {
		t.Fatalf("SubmitContentForReview() error: %v", err)
	}

	const note = "please tighten the intro and add a code sample"
	sentBack, err := s.SendBackForChanges(ctx, id, note)
	if err != nil {
		t.Fatalf("SendBackForChanges() error: %v", err)
	}
	if sentBack.Status != StatusChangesRequested {
		t.Fatalf("SendBackForChanges() status = %q, want %q", sentBack.Status, StatusChangesRequested)
	}

	got, err := s.Content(ctx, id)
	if err != nil {
		t.Fatalf("Content() error: %v", err)
	}
	if got.ReviewNote == nil {
		t.Fatal("Content() review_note = nil, want the owner's send-back note")
	}
	if *got.ReviewNote != note {
		t.Errorf("Content() review_note = %q, want %q", *got.ReviewNote, note)
	}
}

// TestStore_CreateContent_InvalidInput verifies that a client-supplied value
// the database rejects — a foreign key pointing at a non-existent project, or
// a slug that violates chk_content_slug_format — surfaces as ErrInvalidInput
// (which the handler maps to HTTP 400) instead of a wrapped error that
// api.HandleError would render as an opaque 500.
func TestStore_CreateContent_InvalidInput(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	tests := []struct {
		name   string
		mutate func(p *CreateParams)
	}{
		{
			name: "non-existent project_id (foreign key 23503)",
			mutate: func(p *CreateParams) {
				missing := uuid.New()
				p.ProjectID = &missing
			},
		},
		{
			name: "malformed slug (check violation 23514)",
			mutate: func(p *CreateParams) {
				p.Slug = "Not A Valid Slug!"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := &CreateParams{
				Slug:    "valid-slug",
				Title:   "Title",
				Body:    "body",
				Excerpt: "excerpt",
				Type:    TypeTIL,
				Status:  StatusDraft,
			}
			tt.mutate(params)

			if _, err := s.CreateContent(ctx, params); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("CreateContent() err = %v, want ErrInvalidInput", err)
			}
		})
	}
}

// TestStore_UpdateContent_InvalidInput verifies the same FK/CHECK → 400
// classification on the UPDATE path (mapWriteError is shared by CreateContent
// and UpdateContent, so a regression in either would slip past a Create-only test).
func TestStore_UpdateContent_InvalidInput(t *testing.T) {
	setup(t)
	ctx := t.Context()

	existing := createContentTx(t, ctx, &CreateParams{
		Slug:    "update-target",
		Title:   "Title",
		Body:    "body",
		Excerpt: "excerpt",
		Type:    TypeTIL,
		Status:  StatusDraft,
	})

	missing := uuid.New()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := NewStore(tx).UpdateContent(ctx, existing.ID, &UpdateParams{ProjectID: &missing}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("UpdateContent(bad project_id) err = %v, want ErrInvalidInput", err)
	}
}

// TestHandler_PublicBySlug_HidesNonPublic locks the only guard that keeps
// GET /api/contents/{slug} from leaking a private or draft body: the handler's
// !c.IsPublic → 404 check. ContentBySlug itself has no is_public/status filter,
// so if this check is inverted or dropped the private body ships to anonymous
// callers — this test is the regression that would catch it.
func TestHandler_PublicBySlug_HidesNonPublic(t *testing.T) {
	store := setup(t)
	h := NewHandler(store, "http://test.local", slog.New(slog.DiscardHandler))
	ctx := t.Context()

	// A draft is the canonical non-public state (is_public=false by default,
	// chk_content_public_requires_published forbids public-while-unpublished) —
	// exactly what the guard must keep off the public reader.
	if _, err := store.CreateContent(ctx, &CreateParams{
		Slug: "private-piece", Title: "Private Piece", Body: "secret body",
		Excerpt: "secret", Type: TypeArticle, Status: StatusDraft,
	}); err != nil {
		t.Fatalf("creating private draft: %v", err)
	}
	// A published, public piece via the real publish flow, which atomically sets
	// status=published, is_public=true, published_at.
	pub, err := store.CreateContent(ctx, &CreateParams{
		Slug: "public-piece", Title: "Public Piece", Body: "public body",
		Excerpt: "public", Type: TypeArticle, Status: StatusDraft,
	})
	if err != nil {
		t.Fatalf("creating public draft: %v", err)
	}
	bindTestSource(t, pub.ID, "public-piece")
	if _, err := store.PublishContent(ctx, pub.ID); err != nil {
		t.Fatalf("publishing public content: %v", err)
	}

	tests := []struct {
		name     string
		slug     string
		wantCode int
	}{
		{name: "private content is not exposed", slug: "private-piece", wantCode: http.StatusNotFound},
		{name: "public content is served", slug: "public-piece", wantCode: http.StatusOK},
		{name: "missing slug is 404", slug: "nonexistent", wantCode: http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/contents/"+tt.slug, http.NoBody)
			req.SetPathValue("slug", tt.slug)
			w := httptest.NewRecorder()
			h.PublicBySlug(w, req)

			if w.Code != tt.wantCode {
				t.Fatalf("PublicBySlug(%q) status = %d, want %d", tt.slug, w.Code, tt.wantCode)
			}
			if tt.slug == "private-piece" && strings.Contains(w.Body.String(), "secret body") {
				t.Error("PublicBySlug leaked the private body in the response")
			}
		})
	}
}

// TestHandler_SourceProvenanceIsAdminOnly pins the final wire boundary. The
// authenticated detail response exposes a read-only nested source coordinate,
// while the anonymous content response must not serialize either private Vault
// field even though both handlers read the same persisted row.
func TestHandler_SourceProvenanceIsAdminOnly(t *testing.T) {
	store := setup(t)
	h := NewHandler(store, "http://test.local", slog.New(slog.DiscardHandler))

	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(), `
		INSERT INTO contents (
			slug, title, body, excerpt, type, status, is_public, published_at,
			source_vault_path, source_git_blob_sha
		) VALUES (
			'provenance-wire', 'Provenance Wire', 'public body', 'excerpt',
			'article', 'published', true, now(), $1, $2
		) RETURNING id`,
		"Writing/articles/provenance-wire.md",
		"0123456789abcdef0123456789abcdef01234567",
	).Scan(&id); err != nil {
		t.Fatalf("seeding source-bound published row: %v", err)
	}

	adminReq := httptest.NewRequest(http.MethodGet, "/api/admin/knowledge/content/"+id.String(), nil)
	adminReq.SetPathValue("id", id.String())
	adminRec := httptest.NewRecorder()
	h.Get(adminRec, adminReq)
	if adminRec.Code != http.StatusOK {
		t.Fatalf("admin Get status = %d, want 200 (body=%s)", adminRec.Code, adminRec.Body.String())
	}
	var adminBody struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(adminRec.Body.Bytes(), &adminBody); err != nil {
		t.Fatalf("decoding admin response: %v", err)
	}
	sourceRaw, ok := adminBody.Data["source"]
	if !ok {
		t.Fatalf("admin response missing source: %s", adminRec.Body.String())
	}
	var source struct {
		VaultPath  string `json:"vault_path"`
		GitBlobSHA string `json:"git_blob_sha"`
	}
	if err := json.Unmarshal(sourceRaw, &source); err != nil {
		t.Fatalf("decoding admin source: %v", err)
	}
	if source.VaultPath != "Writing/articles/provenance-wire.md" ||
		source.GitBlobSHA != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("admin source = %+v, want exact persisted coordinate", source)
	}

	publicReq := httptest.NewRequest(http.MethodGet, "/api/contents/provenance-wire", nil)
	publicReq.SetPathValue("slug", "provenance-wire")
	publicRec := httptest.NewRecorder()
	h.PublicBySlug(publicRec, publicReq)
	if publicRec.Code != http.StatusOK {
		t.Fatalf("public Get status = %d, want 200 (body=%s)", publicRec.Code, publicRec.Body.String())
	}
	publicJSON := publicRec.Body.String()
	for _, forbidden := range []string{"source", "source_vault_path", "source_git_blob_sha", "Writing/articles/provenance-wire.md"} {
		if strings.Contains(publicJSON, forbidden) {
			t.Fatalf("public response leaked %q: %s", forbidden, publicJSON)
		}
	}
}

// TestSchema_SourceSnapshotConstraints proves the database is the final
// provenance boundary even when a caller bypasses the Go validator.
func TestSchema_SourceSnapshotConstraints(t *testing.T) {
	setup(t)
	const validSHA = "0123456789abcdef0123456789abcdef01234567"
	tests := []struct {
		name string
		path any
		sha  any
	}{
		{name: "half pair path only", path: "Writing/articles/path-only.md", sha: nil},
		{name: "absolute path", path: "/Writing/articles/absolute.md", sha: validSHA},
		{name: "empty segment", path: "Writing//articles/empty.md", sha: validSHA},
		{name: "parent traversal", path: "Writing/../Diary/private.md", sha: validSHA},
		{name: "Diary", path: "Diary/2026-07-20.md", sha: validSHA},
		{name: "non Markdown", path: "Writing/articles/plain.txt", sha: validSHA},
		{name: "invalid SHA", path: "Writing/articles/bad-sha.md", sha: "ABC123"},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := testPool.Exec(t.Context(), `
				INSERT INTO contents (
					slug, title, body, type, status,
					source_vault_path, source_git_blob_sha
				) VALUES ($1, 'Invalid source', 'body', 'article', 'review', $2, $3)`,
				fmt.Sprintf("invalid-source-%d", i), tt.path, tt.sha,
			)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
				t.Fatalf("invalid source insert error = %v, want check violation 23514", err)
			}
		})
	}

	if _, err := testPool.Exec(t.Context(), `
		INSERT INTO contents (
			slug, title, body, type, status,
			source_vault_path, source_git_blob_sha
		) VALUES (
			'valid-source-constraint', 'Valid source', 'body', 'article', 'review', $1, $2
		)`, "Writing/articles/valid-source.md", validSHA,
	); err != nil {
		t.Fatalf("valid source insert rejected: %v", err)
	}
}
