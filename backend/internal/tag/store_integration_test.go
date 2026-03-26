//go:build integration

package tag

import (
	"os"
	"strings"
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
	if err := testdb.TruncateCtx(t.Context(), testPool, "tag_aliases", "obsidian_note_tags", "activity_event_tags", "tags"); err != nil {
		t.Fatal(err)
	}
	return NewStore(testPool)
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
		name            string
		rawTag          string
		wantTagID       bool
		wantMatchMethod string
	}{
		{
			name:            "slug match",
			rawTag:          "TypeScript",
			wantTagID:       true,
			wantMatchMethod: "slug",
		},
		{
			name:            "unmapped tag",
			rawTag:          "totally-unknown-tag",
			wantTagID:       false,
			wantMatchMethod: "unmapped",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.ResolveTag(ctx, tt.rawTag)
			if result.RawTag != tt.rawTag {
				t.Errorf("ResolveTag(%q) raw_tag = %q, want %q", tt.rawTag, result.RawTag, tt.rawTag)
			}
			if result.MatchMethod != tt.wantMatchMethod {
				t.Errorf("ResolveTag(%q) match_method = %q, want %q", tt.rawTag, result.MatchMethod, tt.wantMatchMethod)
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

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("pool.Begin() error: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is no-op after commit

	result, err := s.MergeTags(ctx, tx, source.ID, target.ID)
	if err != nil {
		t.Fatalf("MergeTags(%s, %s) error: %v", source.ID, target.ID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("tx.Commit() error: %v", err)
	}

	// Merge result should report zero moves (no aliases, notes, or events reference source).
	if result.AliasesMoved != 0 {
		t.Errorf("MergeTags() aliases_moved = %d, want 0", result.AliasesMoved)
	}
	if result.NotesMoved != 0 {
		t.Errorf("MergeTags() notes_moved = %d, want 0", result.NotesMoved)
	}
	if result.EventsMoved != 0 {
		t.Errorf("MergeTags() events_moved = %d, want 0", result.EventsMoved)
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

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("pool.Begin() error: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is no-op after commit

	result, err := s.MergeTags(ctx, tx, source.ID, target.ID)
	if err != nil {
		t.Fatalf("MergeTags() error: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("tx.Commit() error: %v", err)
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
	if second.MatchMethod != "exact" {
		t.Errorf("ResolveTag() second call match_method = %q, want %q", second.MatchMethod, "exact")
	}
}

func TestStore_ResolveTag_TooLong(t *testing.T) {
	s := setup(t)

	// A tag longer than maxRawTagLen (255) should return unmapped.
	longTag := strings.Repeat("a", 300)

	result := s.ResolveTag(t.Context(), longTag)
	if result.MatchMethod != "unmapped" {
		t.Errorf("ResolveTag(long) match_method = %q, want %q", result.MatchMethod, "unmapped")
	}
	if result.TagID != nil {
		t.Errorf("ResolveTag(long) tag_id = %s, want nil", *result.TagID)
	}
}
