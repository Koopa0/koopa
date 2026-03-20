package note

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/koopa0/blog-backend/internal/db"
)

// Store manages obsidian knowledge notes in the database.
type Store struct {
	q *db.Queries
}

// NewStore returns a note Store backed by the given connection (pool or tx).
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a new Store that uses the given transaction.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// UpsertNote creates or updates a knowledge note by file_path.
func (s *Store) UpsertNote(ctx context.Context, p UpsertParams) (*Note, error) {
	tagsJSON, err := json.Marshal(p.Tags)
	if err != nil {
		return nil, fmt.Errorf("marshaling tags: %w", err)
	}

	row, err := s.q.UpsertNote(ctx, db.UpsertNoteParams{
		FilePath:     p.FilePath,
		Title:        p.Title,
		Type:         p.Type,
		Source:       p.Source,
		Context:      p.Context,
		Status:       p.Status,
		Tags:         tagsJSON,
		Difficulty:   p.Difficulty,
		LeetcodeID:   p.LeetcodeID,
		Book:         p.Book,
		Chapter:      p.Chapter,
		NotionTaskID: p.NotionTaskID,
		ContentText:  p.ContentText,
		SearchText:   p.SearchText,
		ContentHash:  p.ContentHash,
	})
	if err != nil {
		return nil, fmt.Errorf("upserting note %s: %w", p.FilePath, err)
	}

	n := toNote(row)
	return &n, nil
}

// ContentHash returns the stored content hash for a note, or ErrNotFound if
// the note does not exist. Returns (nil, nil) if the note exists but has no
// hash yet (content_hash column is NULL).
func (s *Store) ContentHash(ctx context.Context, filePath string) (*string, error) {
	hash, err := s.q.NoteContentHash(ctx, filePath)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying content hash for %s: %w", filePath, err)
	}
	return hash, nil
}

// ArchiveNote soft-deletes a note by setting status to 'archived'.
func (s *Store) ArchiveNote(ctx context.Context, filePath string) error {
	return s.q.ArchiveNote(ctx, filePath)
}

// SearchByText performs full-text search on notes and returns ranked results.
func (s *Store) SearchByText(ctx context.Context, query string, limit int) ([]SearchResult, error) {
	rows, err := s.q.SearchNotesByText(ctx, db.SearchNotesByTextParams{
		Query:      query,
		MaxResults: int32(limit), // #nosec G115 -- limit is bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("searching notes by text %q: %w", query, err)
	}
	results := make([]SearchResult, len(rows))
	for i, r := range rows {
		results[i] = SearchResult{
			Note: toNoteFromSearch(r),
			Rank: r.Rank,
		}
	}
	return results, nil
}

// SearchByFilters returns notes matching the given frontmatter filters.
func (s *Store) SearchByFilters(ctx context.Context, f SearchFilter, limit int) ([]Note, error) {
	rows, err := s.q.SearchNotesByFilters(ctx, db.SearchNotesByFiltersParams{
		FilterType:    f.Type,
		FilterSource:  f.Source,
		FilterContext: f.Context,
		FilterBook:    f.Book,
		MaxResults:    int32(limit), // #nosec G115 -- limit is bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("searching notes by filters: %w", err)
	}
	notes := make([]Note, len(rows))
	for i, r := range rows {
		notes[i] = toNoteFromFilterRow(r)
	}
	return notes, nil
}

// NotesByType returns notes of the given type, optionally filtered by context.
func (s *Store) NotesByType(ctx context.Context, noteType string, filterContext *string, limit int) ([]Note, error) {
	rows, err := s.q.NotesByTypeAndContext(ctx, db.NotesByTypeAndContextParams{
		NoteType:      &noteType,
		FilterContext: filterContext,
		MaxResults:    int32(limit), // #nosec G115 -- limit is bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("querying notes by type %s: %w", noteType, err)
	}
	notes := make([]Note, len(rows))
	for i, r := range rows {
		notes[i] = toNoteFromTypeRow(r)
	}
	return notes, nil
}

// SyncNoteLinks replaces all wikilink edges for a note.
// Deletes existing links, then bulk-inserts the new set using unnest
// to avoid N+1 individual INSERT statements.
func (s *Store) SyncNoteLinks(ctx context.Context, noteID int64, links []NoteLink) error {
	if err := s.q.DeleteNoteLinksByNoteID(ctx, noteID); err != nil {
		return fmt.Errorf("deleting note links for note %d: %w", noteID, err)
	}
	if len(links) == 0 {
		return nil
	}
	paths := make([]string, len(links))
	texts := make([]string, len(links))
	for i, l := range links {
		paths[i] = l.TargetPath
		if l.LinkText != nil {
			texts[i] = *l.LinkText
		}
	}
	if err := s.q.BulkUpsertNoteLinks(ctx, db.BulkUpsertNoteLinksParams{
		SourceNoteID: noteID,
		TargetPaths:  paths,
		LinkTexts:    texts,
	}); err != nil {
		return fmt.Errorf("bulk upserting note links for note %d: %w", noteID, err)
	}
	return nil
}

// toNote converts a db.ObsidianNote to a domain Note.
func toNote(row db.ObsidianNote) Note {
	n := Note{
		ID:           row.ID,
		FilePath:     row.FilePath,
		Title:        row.Title,
		Type:         row.Type,
		Source:       row.Source,
		Context:      row.Context,
		Status:       row.Status,
		Difficulty:   row.Difficulty,
		LeetcodeID:   row.LeetcodeID,
		Book:         row.Book,
		Chapter:      row.Chapter,
		NotionTaskID: row.NotionTaskID,
		ContentText:  row.ContentText,
		SearchText:   row.SearchText,
		ContentHash:  row.ContentHash,
		GitCreatedAt: row.GitCreatedAt,
		GitUpdatedAt: row.GitUpdatedAt,
		SyncedAt:     row.SyncedAt,
	}

	// Decode JSONB tags
	if row.Tags != nil {
		_ = json.Unmarshal(row.Tags, &n.Tags) // best-effort
	}
	if n.Tags == nil {
		n.Tags = []string{}
	}

	return n
}

// toNoteFromSearch converts a SearchNotesByTextRow to a domain Note.
func toNoteFromSearch(r db.SearchNotesByTextRow) Note {
	n := Note{
		ID:          r.ID,
		FilePath:    r.FilePath,
		Title:       r.Title,
		Type:        r.Type,
		Source:      r.Source,
		Context:     r.Context,
		Status:      r.Status,
		Difficulty:  r.Difficulty,
		Book:        r.Book,
		Chapter:     r.Chapter,
		ContentText: r.ContentText,
		SyncedAt:    r.SyncedAt,
	}
	if r.Tags != nil {
		_ = json.Unmarshal(r.Tags, &n.Tags) // best-effort
	}
	if n.Tags == nil {
		n.Tags = []string{}
	}
	return n
}

// toNoteFromFilterRow converts a SearchNotesByFiltersRow to a domain Note.
func toNoteFromFilterRow(r db.SearchNotesByFiltersRow) Note {
	n := Note{
		ID:          r.ID,
		FilePath:    r.FilePath,
		Title:       r.Title,
		Type:        r.Type,
		Source:      r.Source,
		Context:     r.Context,
		Status:      r.Status,
		Difficulty:  r.Difficulty,
		Book:        r.Book,
		Chapter:     r.Chapter,
		ContentText: r.ContentText,
		SyncedAt:    r.SyncedAt,
	}
	if r.Tags != nil {
		_ = json.Unmarshal(r.Tags, &n.Tags) // best-effort
	}
	if n.Tags == nil {
		n.Tags = []string{}
	}
	return n
}

// toNoteFromTypeRow converts a NotesByTypeAndContextRow to a domain Note.
func toNoteFromTypeRow(r db.NotesByTypeAndContextRow) Note {
	n := Note{
		ID:          r.ID,
		FilePath:    r.FilePath,
		Title:       r.Title,
		Type:        r.Type,
		Source:      r.Source,
		Context:     r.Context,
		Status:      r.Status,
		Difficulty:  r.Difficulty,
		Book:        r.Book,
		Chapter:     r.Chapter,
		ContentText: r.ContentText,
		SyncedAt:    r.SyncedAt,
	}
	if r.Tags != nil {
		_ = json.Unmarshal(r.Tags, &n.Tags) // best-effort
	}
	if n.Tags == nil {
		n.Tags = []string{}
	}
	return n
}
