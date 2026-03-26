//go:build integration

package note

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
	if err := testdb.TruncateCtx(t.Context(), testPool, "note_links", "obsidian_notes"); err != nil {
		t.Fatal(err)
	}
	return NewStore(testPool)
}

// ptr returns a pointer to v.
func ptr[T any](v T) *T { return &v }

func TestUpsertNote_Insert(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	params := &UpsertParams{
		FilePath:    "notes/go/concurrency.md",
		Title:       ptr("Go Concurrency Patterns"),
		Type:        ptr("note"),
		Source:      ptr("obsidian"),
		Context:     ptr("go"),
		Status:      ptr("seed"),
		Tags:        []string{"go", "concurrency"},
		Difficulty:  ptr("medium"),
		ContentText: ptr("Goroutines and channels are the building blocks of Go concurrency."),
		SearchText:  ptr("go concurrency goroutines channels"),
		ContentHash: ptr("abc123"),
	}

	note, err := s.UpsertNote(ctx, params)
	if err != nil {
		t.Fatalf("UpsertNote(insert) error: %v", err)
	}

	if note.ID == 0 {
		t.Fatal("UpsertNote(insert) returned ID 0")
	}
	if note.FilePath != "notes/go/concurrency.md" {
		t.Errorf("UpsertNote(insert).FilePath = %q, want %q", note.FilePath, "notes/go/concurrency.md")
	}
	if diff := cmp.Diff(ptr("Go Concurrency Patterns"), note.Title); diff != "" {
		t.Errorf("UpsertNote(insert).Title mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(ptr("note"), note.Type); diff != "" {
		t.Errorf("UpsertNote(insert).Type mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(ptr("obsidian"), note.Source); diff != "" {
		t.Errorf("UpsertNote(insert).Source mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(ptr("go"), note.Context); diff != "" {
		t.Errorf("UpsertNote(insert).Context mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(ptr("seed"), note.Status); diff != "" {
		t.Errorf("UpsertNote(insert).Status mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"go", "concurrency"}, note.Tags); diff != "" {
		t.Errorf("UpsertNote(insert).Tags mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(ptr("abc123"), note.ContentHash); diff != "" {
		t.Errorf("UpsertNote(insert).ContentHash mismatch (-want +got):\n%s", diff)
	}
	if note.SyncedAt == nil {
		t.Error("UpsertNote(insert).SyncedAt is nil, want non-nil")
	}
}

func TestUpsertNote_UpdateSameFilePath(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	original := &UpsertParams{
		FilePath:    "notes/go/testing.md",
		Title:       ptr("Go Testing"),
		Type:        ptr("note"),
		Tags:        []string{"go", "testing"},
		ContentHash: ptr("hash-v1"),
		ContentText: ptr("Original content"),
		SearchText:  ptr("go testing"),
	}

	first, err := s.UpsertNote(ctx, original)
	if err != nil {
		t.Fatalf("UpsertNote(insert) error: %v", err)
	}

	// Update the same file_path with new content.
	updated := &UpsertParams{
		FilePath:    "notes/go/testing.md",
		Title:       ptr("Go Testing Best Practices"),
		Type:        ptr("note"),
		Tags:        []string{"go", "testing", "best-practices"},
		ContentHash: ptr("hash-v2"),
		ContentText: ptr("Updated content with best practices"),
		SearchText:  ptr("go testing best practices"),
	}

	second, err := s.UpsertNote(ctx, updated)
	if err != nil {
		t.Fatalf("UpsertNote(update) error: %v", err)
	}

	// Same row: ID must match.
	if second.ID != first.ID {
		t.Errorf("UpsertNote(update).ID = %d, want %d (same row)", second.ID, first.ID)
	}
	if diff := cmp.Diff(ptr("Go Testing Best Practices"), second.Title); diff != "" {
		t.Errorf("UpsertNote(update).Title mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"go", "testing", "best-practices"}, second.Tags); diff != "" {
		t.Errorf("UpsertNote(update).Tags mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(ptr("hash-v2"), second.ContentHash); diff != "" {
		t.Errorf("UpsertNote(update).ContentHash mismatch (-want +got):\n%s", diff)
	}
}

func TestContentHash(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	tests := []struct {
		name     string
		setup    func()
		filePath string
		wantHash *string
		wantErr  error
	}{
		{
			name: "existing note with hash",
			setup: func() {
				_, err := s.UpsertNote(ctx, &UpsertParams{
					FilePath:    "notes/hash-test.md",
					Tags:        []string{},
					ContentHash: ptr("sha256-abc"),
				})
				if err != nil {
					t.Fatalf("setup UpsertNote error: %v", err)
				}
			},
			filePath: "notes/hash-test.md",
			wantHash: ptr("sha256-abc"),
		},
		{
			name: "existing note without hash",
			setup: func() {
				_, err := s.UpsertNote(ctx, &UpsertParams{
					FilePath: "notes/no-hash.md",
					Tags:     []string{},
				})
				if err != nil {
					t.Fatalf("setup UpsertNote error: %v", err)
				}
			},
			filePath: "notes/no-hash.md",
			wantHash: nil,
		},
		{
			name:     "missing note",
			setup:    func() {},
			filePath: "notes/does-not-exist.md",
			wantErr:  ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testdb.Truncate(t, testPool, "note_links", "obsidian_notes")
			tt.setup()

			hash, err := s.ContentHash(ctx, tt.filePath)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Fatalf("ContentHash(%q) error = %v, want %v", tt.filePath, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ContentHash(%q) unexpected error: %v", tt.filePath, err)
			}
			if diff := cmp.Diff(tt.wantHash, hash); diff != "" {
				t.Errorf("ContentHash(%q) mismatch (-want +got):\n%s", tt.filePath, diff)
			}
		})
	}
}

func TestArchiveNote(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create a note with default status.
	note, err := s.UpsertNote(ctx, &UpsertParams{
		FilePath: "notes/to-archive.md",
		Title:    ptr("Archive me"),
		Status:   ptr("seed"),
		Tags:     []string{},
	})
	if err != nil {
		t.Fatalf("UpsertNote() error: %v", err)
	}
	if diff := cmp.Diff(ptr("seed"), note.Status); diff != "" {
		t.Fatalf("initial status mismatch (-want +got):\n%s", diff)
	}

	// Archive it.
	if err := s.ArchiveNote(ctx, "notes/to-archive.md"); err != nil {
		t.Fatalf("ArchiveNote(%q) error: %v", "notes/to-archive.md", err)
	}

	// Verify status changed to archived via ContentHash (still accessible).
	// Re-read via upsert to check the status. Since archived notes
	// won't appear in search results, verify by upserting with same file_path.
	archived, err := s.UpsertNote(ctx, &UpsertParams{
		FilePath: "notes/to-archive.md",
		Title:    ptr("Archive me"),
		Status:   ptr("seed"),
		Tags:     []string{},
	})
	if err != nil {
		t.Fatalf("UpsertNote(re-read) error: %v", err)
	}
	// Upsert overwrites status, so it will be "seed" again.
	// Instead, archive again and check that the search excludes it.
	if err := s.ArchiveNote(ctx, archived.FilePath); err != nil {
		t.Fatalf("ArchiveNote() second call error: %v", err)
	}

	// Archived notes should not appear in text search.
	results, err := s.SearchByText(ctx, "Archive", 10)
	if err != nil {
		t.Fatalf("SearchByText(%q) error: %v", "Archive", err)
	}
	if len(results) != 0 {
		t.Errorf("SearchByText(%q) returned %d results for archived note, want 0", "Archive", len(results))
	}
}

func TestSearchByText(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create notes with different content.
	seeds := []struct {
		filePath   string
		title      string
		searchText string
	}{
		{"notes/go/channels.md", "Go Channels", "go channels communication concurrency"},
		{"notes/go/goroutines.md", "Go Goroutines", "go goroutines lightweight threads"},
		{"notes/rust/ownership.md", "Rust Ownership", "rust ownership borrowing memory"},
	}
	for _, seed := range seeds {
		_, err := s.UpsertNote(ctx, &UpsertParams{
			FilePath:   seed.filePath,
			Title:      ptr(seed.title),
			Tags:       []string{},
			SearchText: ptr(seed.searchText),
		})
		if err != nil {
			t.Fatalf("UpsertNote(%q) error: %v", seed.filePath, err)
		}
	}

	// Search for "go" should match the two Go notes.
	results, err := s.SearchByText(ctx, "go", 10)
	if err != nil {
		t.Fatalf("SearchByText(%q) error: %v", "go", err)
	}
	if len(results) != 2 {
		t.Errorf("SearchByText(%q) count = %d, want 2", "go", len(results))
	}

	// Search for "rust" should match only the Rust note.
	results, err = s.SearchByText(ctx, "rust", 10)
	if err != nil {
		t.Fatalf("SearchByText(%q) error: %v", "rust", err)
	}
	if len(results) != 1 {
		t.Fatalf("SearchByText(%q) count = %d, want 1", "rust", len(results))
	}
	if results[0].FilePath != "notes/rust/ownership.md" {
		t.Errorf("SearchByText(%q)[0].FilePath = %q, want %q", "rust", results[0].FilePath, "notes/rust/ownership.md")
	}
	if results[0].Rank <= 0 {
		t.Errorf("SearchByText(%q)[0].Rank = %f, want > 0", "rust", results[0].Rank)
	}
}

func TestSearchByFilters(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create notes with different type/context.
	seeds := []struct {
		filePath string
		noteType string
		context  string
	}{
		{"notes/go/note1.md", "note", "go"},
		{"notes/go/note2.md", "note", "go"},
		{"notes/rust/note1.md", "note", "rust"},
		{"notes/go/decision1.md", "decision", "go"},
	}
	for _, seed := range seeds {
		_, err := s.UpsertNote(ctx, &UpsertParams{
			FilePath: seed.filePath,
			Type:     ptr(seed.noteType),
			Context:  ptr(seed.context),
			Tags:     []string{},
		})
		if err != nil {
			t.Fatalf("UpsertNote(%q) error: %v", seed.filePath, err)
		}
	}

	tests := []struct {
		name      string
		filter    SearchFilter
		wantCount int
	}{
		{
			name:      "filter by type=note",
			filter:    SearchFilter{Type: ptr("note")},
			wantCount: 3,
		},
		{
			name:      "filter by context=go",
			filter:    SearchFilter{Context: ptr("go")},
			wantCount: 3,
		},
		{
			name:      "filter by type=note AND context=go",
			filter:    SearchFilter{Type: ptr("note"), Context: ptr("go")},
			wantCount: 2,
		},
		{
			name:      "filter by type=decision",
			filter:    SearchFilter{Type: ptr("decision")},
			wantCount: 1,
		},
		{
			name:      "no matching filter",
			filter:    SearchFilter{Type: ptr("article")},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notes, err := s.SearchByFilters(ctx, tt.filter, 100)
			if err != nil {
				t.Fatalf("SearchByFilters(%+v) error: %v", tt.filter, err)
			}
			if len(notes) != tt.wantCount {
				t.Errorf("SearchByFilters(%+v) count = %d, want %d", tt.filter, len(notes), tt.wantCount)
			}
		})
	}
}

func TestSyncNoteLinks(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create a source note.
	note, err := s.UpsertNote(ctx, &UpsertParams{
		FilePath: "notes/go/main.md",
		Title:    ptr("Go Main"),
		Tags:     []string{},
	})
	if err != nil {
		t.Fatalf("UpsertNote() error: %v", err)
	}

	// Sync initial links.
	links := []Link{
		{TargetPath: "notes/go/channels.md", LinkText: ptr("channels")},
		{TargetPath: "notes/go/goroutines.md", LinkText: ptr("goroutines")},
	}
	if err := s.SyncNoteLinks(ctx, note.ID, links); err != nil {
		t.Fatalf("SyncNoteLinks(initial) error: %v", err)
	}

	// Re-sync with different links (should replace).
	newLinks := []Link{
		{TargetPath: "notes/go/channels.md", LinkText: ptr("channels updated")},
		{TargetPath: "notes/go/testing.md", LinkText: ptr("testing")},
		{TargetPath: "notes/go/errors.md"},
	}
	if err := s.SyncNoteLinks(ctx, note.ID, newLinks); err != nil {
		t.Fatalf("SyncNoteLinks(replace) error: %v", err)
	}

	// Verify link count by querying directly.
	var count int
	err = testPool.QueryRow(ctx,
		"SELECT count(*) FROM note_links WHERE source_note_id = $1", note.ID).Scan(&count)
	if err != nil {
		t.Fatalf("counting note_links error: %v", err)
	}
	if count != 3 {
		t.Errorf("note_links count = %d, want 3", count)
	}

	// Sync with empty links should remove all.
	if err := s.SyncNoteLinks(ctx, note.ID, nil); err != nil {
		t.Fatalf("SyncNoteLinks(empty) error: %v", err)
	}
	err = testPool.QueryRow(ctx,
		"SELECT count(*) FROM note_links WHERE source_note_id = $1", note.ID).Scan(&count)
	if err != nil {
		t.Fatalf("counting note_links after clear error: %v", err)
	}
	if count != 0 {
		t.Errorf("note_links count after clear = %d, want 0", count)
	}
}

func TestNotesByType(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create notes with mixed types.
	seeds := []struct {
		filePath string
		noteType string
		context  string
	}{
		{"notes/n1.md", "note", "go"},
		{"notes/n2.md", "note", "rust"},
		{"notes/d1.md", "decision", "go"},
	}
	for _, seed := range seeds {
		_, err := s.UpsertNote(ctx, &UpsertParams{
			FilePath: seed.filePath,
			Type:     ptr(seed.noteType),
			Context:  ptr(seed.context),
			Tags:     []string{},
		})
		if err != nil {
			t.Fatalf("UpsertNote(%q) error: %v", seed.filePath, err)
		}
	}

	// Query by type "note" without context filter.
	notes, err := s.NotesByType(ctx, "note", nil, 100)
	if err != nil {
		t.Fatalf("NotesByType(%q, nil) error: %v", "note", err)
	}
	if len(notes) != 2 {
		t.Errorf("NotesByType(%q, nil) count = %d, want 2", "note", len(notes))
	}

	// Query by type "note" with context "go".
	goCtx := "go"
	notes, err = s.NotesByType(ctx, "note", &goCtx, 100)
	if err != nil {
		t.Fatalf("NotesByType(%q, %q) error: %v", "note", "go", err)
	}
	if len(notes) != 1 {
		t.Errorf("NotesByType(%q, %q) count = %d, want 1", "note", "go", len(notes))
	}
}

func TestUpsertNote_NilTags(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Tags as nil should be stored as empty JSON array and returned as empty slice.
	note, err := s.UpsertNote(ctx, &UpsertParams{
		FilePath: "notes/nil-tags.md",
		Tags:     nil,
	})
	if err != nil {
		t.Fatalf("UpsertNote(nil tags) error: %v", err)
	}

	// Tags should default to empty slice, never nil.
	if note.Tags == nil {
		t.Fatal("UpsertNote(nil tags).Tags is nil, want empty slice")
	}
	if diff := cmp.Diff([]string{}, note.Tags, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("UpsertNote(nil tags).Tags mismatch (-want +got):\n%s", diff)
	}
}

func TestNotesWithoutEmbedding(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create notes (all will lack embeddings initially).
	for _, fp := range []string{"notes/e1.md", "notes/e2.md"} {
		_, err := s.UpsertNote(ctx, &UpsertParams{
			FilePath:    fp,
			Title:       ptr("Embedding test " + fp),
			ContentText: ptr("Some content for " + fp),
			Tags:        []string{},
		})
		if err != nil {
			t.Fatalf("UpsertNote(%q) error: %v", fp, err)
		}
	}

	candidates, err := s.NotesWithoutEmbedding(ctx, 10)
	if err != nil {
		t.Fatalf("NotesWithoutEmbedding() error: %v", err)
	}
	if len(candidates) != 2 {
		t.Errorf("NotesWithoutEmbedding() count = %d, want 2", len(candidates))
	}
	for _, c := range candidates {
		if c.ID == 0 {
			t.Error("NotesWithoutEmbedding() returned candidate with ID 0")
		}
		if c.FilePath == "" {
			t.Error("NotesWithoutEmbedding() returned candidate with empty FilePath")
		}
	}
}
