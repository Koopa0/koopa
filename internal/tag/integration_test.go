//go:build integration

package tag

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool

	// bookmarks.curated_by FKs onto agents(name). Sync the builtin
	// registry so TestStore_MergeTags_PreservesContentAndBookmarkAttachments
	// can insert a bookmark row without a 23503 FK violation.
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

func setup(t *testing.T) *Store {
	t.Helper()
	if err := testdb.TruncateCtx(t.Context(), testPool, "tag_aliases", "tags"); err != nil {
		t.Fatal(err)
	}
	return NewStore(testPool)
}

// setupWithJunctions is the same as setup but also truncates the
// content and bookmark tables (and their tag junctions) so a merge
// test can seed fresh rows without colliding on unique constraints.
// TRUNCATE CASCADE on tags already removes junction rows, but
// contents and bookmarks rows themselves persist across tests and
// must be cleared explicitly.
func setupWithJunctions(t *testing.T) *Store {
	t.Helper()
	if err := testdb.TruncateCtx(t.Context(), testPool,
		"content_tags", "bookmark_tags", "contents", "bookmarks", "tag_aliases", "tags",
	); err != nil {
		t.Fatal(err)
	}
	return NewStore(testPool)
}

// randomHex returns a crypto/rand-backed hex string for generating
// unique slugs and URLs so successive seed calls don't collide on
// unique constraints.
func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("crypto/rand read: %v", err)
	}
	return hex.EncodeToString(b)
}

// seedContent inserts a minimal contents row via raw SQL (the contents
// package is out of scope here). Returns the row id.
func seedContent(t *testing.T, slug string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := testPool.QueryRow(t.Context(), `
		INSERT INTO contents (slug, title, type, status)
		VALUES ($1, $2, 'article', 'draft')
		RETURNING id
	`, slug, "Title "+slug).Scan(&id)
	if err != nil {
		t.Fatalf("seedContent(%q) error: %v", slug, err)
	}
	return id
}

// seedBookmark inserts a minimal bookmarks row via raw SQL (the
// bookmark package is out of scope here). Returns the row id.
func seedBookmark(t *testing.T, slug string) uuid.UUID {
	t.Helper()
	// url_hash must be a 64-char lowercase hex (chk_bookmark_url_hash_format).
	urlHash := randomHex(t, 32)
	url := "https://example.com/" + slug
	var id uuid.UUID
	err := testPool.QueryRow(t.Context(), `
		INSERT INTO bookmarks (url, url_hash, slug, title, capture_channel, curated_by)
		VALUES ($1, $2, $3, $4, 'manual', 'human')
		RETURNING id
	`, url, urlHash, slug, "Title "+slug).Scan(&id)
	if err != nil {
		t.Fatalf("seedBookmark(%q) error: %v", slug, err)
	}
	return id
}

// attachContentTag inserts a row into content_tags.
func attachContentTag(t *testing.T, contentID, tagID uuid.UUID) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO content_tags (content_id, tag_id) VALUES ($1, $2)`,
		contentID, tagID,
	); err != nil {
		t.Fatalf("attachContentTag(%s, %s) error: %v", contentID, tagID, err)
	}
}

// attachBookmarkTag inserts a row into bookmark_tags.
func attachBookmarkTag(t *testing.T, bookmarkID, tagID uuid.UUID) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO bookmark_tags (bookmark_id, tag_id) VALUES ($1, $2)`,
		bookmarkID, tagID,
	); err != nil {
		t.Fatalf("attachBookmarkTag(%s, %s) error: %v", bookmarkID, tagID, err)
	}
}

// cmpTagOpts are reusable cmp options for Tag comparison.
var cmpTagOpts = cmp.Options{
	cmpopts.EquateApproxTime(time.Second),
}

// seedTag creates a canonical tag for use in tests.
func seedTag(t *testing.T, s *Store, slug, name string) *Tag {
	t.Helper()
	tag, err := s.CreateTag(t.Context(), &CreateParams{
		Slug: slug,
		Name: name,
	})
	if err != nil {
		t.Fatalf("seedTag(%q) error: %v", slug, err)
	}
	return tag
}

func TestStore_CreateTag_and_Tag(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	params := &CreateParams{
		Slug:        "golang",
		Name:        "Go",
		Description: "The Go programming language",
	}

	created, err := s.CreateTag(ctx, params)
	if err != nil {
		t.Fatalf("CreateTag() error: %v", err)
	}

	if created.ID == uuid.Nil {
		t.Fatal("CreateTag() returned nil ID")
	}
	if created.Slug != "golang" {
		t.Errorf("CreateTag() slug = %q, want %q", created.Slug, "golang")
	}

	// Round-trip: read back by ID.
	got, err := s.Tag(ctx, created.ID)
	if err != nil {
		t.Fatalf("Tag(%s) error: %v", created.ID, err)
	}

	want := &Tag{
		ID:          created.ID,
		Slug:        "golang",
		Name:        "Go",
		Description: "The Go programming language",
		CreatedAt:   created.CreatedAt,
		UpdatedAt:   created.UpdatedAt,
	}

	if diff := cmp.Diff(want, got, cmpTagOpts); diff != "" {
		t.Errorf("Tag(%s) mismatch (-want +got):\n%s", created.ID, diff)
	}
}

func TestStore_CreateTag_DuplicateSlug(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	params := &CreateParams{Slug: "dup-tag", Name: "Dup"}

	if _, err := s.CreateTag(ctx, params); err != nil {
		t.Fatalf("CreateTag() first call error: %v", err)
	}

	_, err := s.CreateTag(ctx, params)
	if err != ErrConflict {
		t.Fatalf("CreateTag(duplicate slug) = %v, want ErrConflict", err)
	}
}

func TestStore_Tag_NotFound(t *testing.T) {
	s := setup(t)

	_, err := s.Tag(t.Context(), uuid.New())
	if err != ErrNotFound {
		t.Fatalf("Tag(missing ID) = %v, want ErrNotFound", err)
	}
}

func TestStore_Tags(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	slugs := []string{"alpha", "beta", "gamma"}
	for _, slug := range slugs {
		seedTag(t, s, slug, "Tag "+slug)
	}

	tags, err := s.Tags(ctx)
	if err != nil {
		t.Fatalf("Tags() error: %v", err)
	}

	if len(tags) < len(slugs) {
		t.Errorf("Tags() len = %d, want >= %d", len(tags), len(slugs))
	}

	// Verify all created tags are present (ordered by name).
	gotSlugs := make(map[string]bool, len(tags))
	for _, tag := range tags {
		gotSlugs[tag.Slug] = true
	}
	for _, slug := range slugs {
		if !gotSlugs[slug] {
			t.Errorf("Tags() missing slug %q", slug)
		}
	}
}

func TestStore_UpdateTag(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	created := seedTag(t, s, "update-tag", "Original")

	newName := "Updated"
	newDesc := "Updated description"
	updated, err := s.UpdateTag(ctx, created.ID, &UpdateParams{
		Name:        &newName,
		Description: &newDesc,
	})
	if err != nil {
		t.Fatalf("UpdateTag(%s) error: %v", created.ID, err)
	}

	if updated.Name != newName {
		t.Errorf("UpdateTag() name = %q, want %q", updated.Name, newName)
	}
	if updated.Description != newDesc {
		t.Errorf("UpdateTag() description = %q, want %q", updated.Description, newDesc)
	}
	// Slug should remain unchanged.
	if updated.Slug != created.Slug {
		t.Errorf("UpdateTag() slug = %q, want %q (unchanged)", updated.Slug, created.Slug)
	}
}

func TestStore_UpdateTag_NotFound(t *testing.T) {
	s := setup(t)

	newName := "whatever"
	_, err := s.UpdateTag(t.Context(), uuid.New(), &UpdateParams{
		Name: &newName,
	})
	if err != ErrNotFound {
		t.Fatalf("UpdateTag(missing ID) = %v, want ErrNotFound", err)
	}
}

func TestStore_UpdateTag_DuplicateSlug(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	seedTag(t, s, "slug-a", "Tag A")
	tagB := seedTag(t, s, "slug-b", "Tag B")

	// Attempt to update tagB's slug to tagA's slug.
	newSlug := "slug-a"
	_, err := s.UpdateTag(ctx, tagB.ID, &UpdateParams{Slug: &newSlug})
	if err != ErrConflict {
		t.Fatalf("UpdateTag(duplicate slug) = %v, want ErrConflict", err)
	}
}

func TestStore_DeleteTag(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	created := seedTag(t, s, "delete-tag", "Delete Me")

	if err := s.DeleteTag(ctx, created.ID); err != nil {
		t.Fatalf("DeleteTag(%s) error: %v", created.ID, err)
	}

	// Verify the tag is gone.
	_, err := s.Tag(ctx, created.ID)
	if err != ErrNotFound {
		t.Fatalf("Tag(%s) after delete = %v, want ErrNotFound", created.ID, err)
	}
}

func TestStore_ResolveTag(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	created := seedTag(t, s, "typescript", "TypeScript")

	tests := []struct {
		name                 string
		rawTag               string
		wantTagID            bool
		wantResolutionSource string
	}{
		{
			name:                 "slug match",
			rawTag:               "TypeScript",
			wantTagID:            true,
			wantResolutionSource: "auto-slug",
		},
		{
			name:                 "unmapped tag",
			rawTag:               "totally-unknown-tag",
			wantTagID:            false,
			wantResolutionSource: "unmapped",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.ResolveTag(ctx, tt.rawTag)
			if result.RawTag != tt.rawTag {
				t.Errorf("ResolveTag(%q) raw_tag = %q, want %q", tt.rawTag, result.RawTag, tt.rawTag)
			}
			if result.ResolutionSource != tt.wantResolutionSource {
				t.Errorf("ResolveTag(%q) resolution_source = %q, want %q", tt.rawTag, result.ResolutionSource, tt.wantResolutionSource)
			}
			if tt.wantTagID {
				if result.TagID == nil {
					t.Fatalf("ResolveTag(%q) tag_id is nil, want non-nil", tt.rawTag)
				}
				if *result.TagID != created.ID {
					t.Errorf("ResolveTag(%q) tag_id = %s, want %s", tt.rawTag, *result.TagID, created.ID)
				}
			} else {
				if result.TagID != nil {
					t.Errorf("ResolveTag(%q) tag_id = %s, want nil", tt.rawTag, *result.TagID)
				}
			}
		})
	}
}

func TestStore_ResolveTags_Batch(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	seedTag(t, s, "rust", "Rust")
	seedTag(t, s, "python", "Python")

	// First resolve to create aliases via slug match.
	s.ResolveTag(ctx, "Rust")
	s.ResolveTag(ctx, "Python")

	// Now batch resolve: the exact aliases exist from the first resolve.
	results := s.ResolveTags(ctx, []string{"Rust", "Python", "unknown-lang"})
	if len(results) != 3 {
		t.Fatalf("ResolveTags() len = %d, want 3", len(results))
	}

	mapped := 0
	for _, r := range results {
		if r.TagID != nil {
			mapped++
		}
	}
	if mapped != 2 {
		t.Errorf("ResolveTags() mapped = %d, want 2", mapped)
	}
}

func TestStore_ResolveTags_Empty(t *testing.T) {
	s := setup(t)

	results := s.ResolveTags(t.Context(), nil)
	if results != nil {
		t.Errorf("ResolveTags(nil) = %v, want nil", results)
	}

	results = s.ResolveTags(t.Context(), []string{})
	if results != nil {
		t.Errorf("ResolveTags([]) = %v, want nil", results)
	}
}

func TestStore_MergeTags(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	source := seedTag(t, s, "merge-source", "Source Tag")
	target := seedTag(t, s, "merge-target", "Target Tag")

	// MergeTags owns its own transaction — the store begins and commits
	// internally, so the caller passes IDs only.
	result, err := s.MergeTags(ctx, source.ID, target.ID)
	if err != nil {
		t.Fatalf("MergeTags(%s, %s) error: %v", source.ID, target.ID, err)
	}

	// No aliases reference source, so aliases_moved should be zero.
	if result.AliasesMoved != 0 {
		t.Errorf("MergeTags() aliases_moved = %d, want 0", result.AliasesMoved)
	}

	// Source tag should be deleted.
	_, err = s.Tag(ctx, source.ID)
	if err != ErrNotFound {
		t.Fatalf("Tag(%s) after merge = %v, want ErrNotFound", source.ID, err)
	}

	// Target tag should still exist.
	_, err = s.Tag(ctx, target.ID)
	if err != nil {
		t.Fatalf("Tag(%s) after merge error: %v", target.ID, err)
	}
}

func TestStore_MergeTags_WithAlias(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	source := seedTag(t, s, "merge-src-alias", "Source With Alias")
	target := seedTag(t, s, "merge-tgt-alias", "Target With Alias")

	// Create an alias pointing to source by resolving a raw tag through slug match.
	// "Merge-Src-Alias" will slugify to "merge-src-alias" and match the source tag.
	s.ResolveTag(ctx, "Merge-Src-Alias")

	result, err := s.MergeTags(ctx, source.ID, target.ID)
	if err != nil {
		t.Fatalf("MergeTags() error: %v", err)
	}

	if result.AliasesMoved < 1 {
		t.Errorf("MergeTags() aliases_moved = %d, want >= 1", result.AliasesMoved)
	}

	// Source tag should be deleted.
	_, err = s.Tag(ctx, source.ID)
	if err != ErrNotFound {
		t.Fatalf("Tag(%s) after merge = %v, want ErrNotFound", source.ID, err)
	}
}

// TestStore_MergeTags_PreservesContentAndBookmarkAttachments is the
// regression guard for the silent data-loss bug in the old MergeTags:
// before the fix, DeleteTag on the source cascaded away every
// content_tags / bookmark_tags row referencing it. After the fix, those
// junction rows are reassigned to the target before the source is
// deleted, and MergeResult reports the counts moved.
func TestStore_MergeTags_PreservesContentAndBookmarkAttachments(t *testing.T) {
	s := setupWithJunctions(t)
	ctx := t.Context()

	source := seedTag(t, s, "merge-src-junctions", "Source With Junctions")
	target := seedTag(t, s, "merge-tgt-junctions", "Target With Junctions")

	// Two contents, both tagged with source only.
	content1 := seedContent(t, "content-"+randomHex(t, 8))
	content2 := seedContent(t, "content-"+randomHex(t, 8))
	attachContentTag(t, content1, source.ID)
	attachContentTag(t, content2, source.ID)

	// One bookmark tagged with source only.
	bookmark := seedBookmark(t, "bookmark-"+randomHex(t, 8))
	attachBookmarkTag(t, bookmark, source.ID)

	result, err := s.MergeTags(ctx, source.ID, target.ID)
	if err != nil {
		t.Fatalf("MergeTags(%s, %s) error: %v", source.ID, target.ID, err)
	}

	if result.ContentTagsMoved != 2 {
		t.Errorf("MergeTags() content_tags_moved = %d, want 2", result.ContentTagsMoved)
	}
	if result.BookmarkTagsMoved != 1 {
		t.Errorf("MergeTags() bookmark_tags_moved = %d, want 1", result.BookmarkTagsMoved)
	}

	// No content_tags / bookmark_tags row may reference the source tag
	// — those rows were either reassigned (preferred) or silently
	// cascaded away by the old buggy path.
	var remainingContent int
	if err := testPool.QueryRow(ctx,
		`SELECT count(*)::int FROM content_tags WHERE tag_id = $1`, source.ID,
	).Scan(&remainingContent); err != nil {
		t.Fatalf("counting remaining source content_tags: %v", err)
	}
	if remainingContent != 0 {
		t.Fatalf("MergeTags() content_tags remaining on source = %d, want 0", remainingContent)
	}

	var remainingBookmark int
	if err := testPool.QueryRow(ctx,
		`SELECT count(*)::int FROM bookmark_tags WHERE tag_id = $1`, source.ID,
	).Scan(&remainingBookmark); err != nil {
		t.Fatalf("counting remaining source bookmark_tags: %v", err)
	}
	if remainingBookmark != 0 {
		t.Fatalf("MergeTags() bookmark_tags remaining on source = %d, want 0", remainingBookmark)
	}

	// Both contents must now be tagged with target (reassigned, not
	// cascaded).
	var contentOnTarget int
	if err := testPool.QueryRow(ctx,
		`SELECT count(*)::int FROM content_tags WHERE tag_id = $1 AND content_id IN ($2, $3)`,
		target.ID, content1, content2,
	).Scan(&contentOnTarget); err != nil {
		t.Fatalf("counting target content_tags: %v", err)
	}
	if contentOnTarget != 2 {
		t.Fatalf("MergeTags() content_tags on target = %d, want 2", contentOnTarget)
	}

	// Bookmark must now be tagged with target.
	var bookmarkOnTarget int
	if err := testPool.QueryRow(ctx,
		`SELECT count(*)::int FROM bookmark_tags WHERE tag_id = $1 AND bookmark_id = $2`,
		target.ID, bookmark,
	).Scan(&bookmarkOnTarget); err != nil {
		t.Fatalf("counting target bookmark_tags: %v", err)
	}
	if bookmarkOnTarget != 1 {
		t.Fatalf("MergeTags() bookmark_tags on target = %d, want 1", bookmarkOnTarget)
	}

	// Source tag itself must be gone.
	if _, err := s.Tag(ctx, source.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Tag(%s) after merge = %v, want ErrNotFound", source.ID, err)
	}
}

func TestStore_DeleteTag_HasReferences(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	created := seedTag(t, s, "referenced-tag", "Referenced")

	// Create an alias pointing to this tag by resolving a raw tag through slug match.
	s.ResolveTag(ctx, "Referenced-Tag")

	err := s.DeleteTag(ctx, created.ID)
	if err != ErrHasReferences {
		t.Fatalf("DeleteTag(tag with alias) = %v, want ErrHasReferences", err)
	}
}

func TestStore_ResolveTag_ExactAliasMatch(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	created := seedTag(t, s, "exact-match", "Exact Match")

	// First resolve creates a slug-based alias.
	first := s.ResolveTag(ctx, "Exact-Match")
	if first.TagID == nil || *first.TagID != created.ID {
		t.Fatalf("ResolveTag() first call: tag_id = %v, want %s", first.TagID, created.ID)
	}

	// Second resolve should hit the exact alias created by the first call.
	second := s.ResolveTag(ctx, "Exact-Match")
	if second.TagID == nil || *second.TagID != created.ID {
		t.Fatalf("ResolveTag() second call: tag_id = %v, want %s", second.TagID, created.ID)
	}
	if second.ResolutionSource != "auto-exact" {
		t.Errorf("ResolveTag() second call resolution_source = %q, want %q", second.ResolutionSource, "auto-exact")
	}
}

func TestStore_ResolveTag_TooLong(t *testing.T) {
	s := setup(t)

	// A tag longer than maxRawTagLen (255) should return unmapped.
	longTag := strings.Repeat("a", 300)

	result := s.ResolveTag(t.Context(), longTag)
	if result.ResolutionSource != "unmapped" {
		t.Errorf("ResolveTag(long) resolution_source = %q, want %q", result.ResolutionSource, "unmapped")
	}
	if result.TagID != nil {
		t.Errorf("ResolveTag(long) tag_id = %s, want nil", *result.TagID)
	}
}
