package note

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	pgvector "github.com/pgvector/pgvector-go"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// derefOr returns the dereferenced pointer value, or the fallback if nil.
func derefOr(p *string, fallback string) string {
	if p != nil {
		return *p
	}
	return fallback
}

// Store manages obsidian knowledge notes in the database.
type Store struct {
	q *db.Queries
}

// NewStore returns a note Store backed by the given connection (pool or tx).
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// UpsertNote creates or updates a knowledge note by file_path.
func (s *Store) UpsertNote(ctx context.Context, p *UpsertParams) (*Note, error) {
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
		Maturity:     derefOr(p.Maturity, "seed"),
		RawTags:      tagsJSON,
		Difficulty:   p.Difficulty,
		LeetcodeID:   p.LeetcodeID,
		Book:         p.Book,
		Chapter:      p.Chapter,
		NotionTaskID: p.NotionTaskID,
		ContentText:  p.ContentText,
		ContentHash:  p.ContentHash,
	})
	if err != nil {
		return nil, fmt.Errorf("upserting note %s: %w", p.FilePath, err)
	}

	n := toNote(&row)
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
	for i := range rows {
		results[i] = SearchResult{
			Note: toNoteFromSearch(&rows[i]),
			Rank: rows[i].Rank,
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
		After:         f.After,
		Before:        f.Before,
		MaxResults:    int32(limit), // #nosec G115 -- limit is bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("searching notes by filters: %w", err)
	}
	notes := make([]Note, len(rows))
	for i := range rows {
		notes[i] = toNoteFromFilterRow(&rows[i])
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
	for i := range rows {
		notes[i] = toNoteFromTypeRow(&rows[i])
	}
	return notes, nil
}

// SyncNoteLinks replaces all wikilink edges for a note.
// Deletes existing links, then bulk-inserts the new set using unnest
// to avoid N+1 individual INSERT statements.
func (s *Store) SyncNoteLinks(ctx context.Context, noteID int64, links []Link) error {
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

// toNote converts a db.Note to a domain Note.
func toNote(row *db.Note) Note {
	n := Note{
		ID:           row.ID,
		FilePath:     row.FilePath,
		Title:        row.Title,
		Type:         row.Type,
		Source:       row.Source,
		Context:      row.Context,
		Maturity:     &row.Maturity,
		Difficulty:   row.Difficulty,
		LeetcodeID:   row.LeetcodeID,
		Book:         row.Book,
		Chapter:      row.Chapter,
		NotionTaskID: row.NotionTaskID,
		ContentText:  row.ContentText,
		ContentHash:  row.ContentHash,
		GitCreatedAt: row.GitCreatedAt,
		GitUpdatedAt: row.GitUpdatedAt,
		SyncedAt:     &row.SyncedAt,
	}

	// Decode JSONB tags
	if row.RawTags != nil {
		_ = json.Unmarshal(row.RawTags, &n.Tags) // best-effort
	}
	if n.Tags == nil {
		n.Tags = []string{}
	}

	return n
}

// toNoteFromSearch converts a SearchNotesByTextRow to a domain Note.
func toNoteFromSearch(r *db.SearchNotesByTextRow) Note {
	n := Note{
		ID:          r.ID,
		FilePath:    r.FilePath,
		Title:       r.Title,
		Type:        r.Type,
		Source:      r.Source,
		Context:     r.Context,
		Maturity:    &r.Maturity,
		Difficulty:  r.Difficulty,
		Book:        r.Book,
		Chapter:     r.Chapter,
		ContentText: r.ContentText,
		SyncedAt:    &r.SyncedAt,
	}
	if r.RawTags != nil {
		_ = json.Unmarshal(r.RawTags, &n.Tags) // best-effort
	}
	if n.Tags == nil {
		n.Tags = []string{}
	}
	return n
}

// toNoteFromFilterRow converts a SearchNotesByFiltersRow to a domain Note.
func toNoteFromFilterRow(r *db.SearchNotesByFiltersRow) Note {
	n := Note{
		ID:          r.ID,
		FilePath:    r.FilePath,
		Title:       r.Title,
		Type:        r.Type,
		Source:      r.Source,
		Context:     r.Context,
		Maturity:    &r.Maturity,
		Difficulty:  r.Difficulty,
		Book:        r.Book,
		Chapter:     r.Chapter,
		ContentText: r.ContentText,
		SyncedAt:    &r.SyncedAt,
	}
	if r.RawTags != nil {
		_ = json.Unmarshal(r.RawTags, &n.Tags) // best-effort
	}
	if n.Tags == nil {
		n.Tags = []string{}
	}
	return n
}

// UpdateEmbedding stores an embedding vector for a note.
func (s *Store) UpdateEmbedding(ctx context.Context, id int64, vec pgvector.Vector) error {
	if err := s.q.UpdateNoteEmbedding(ctx, db.UpdateNoteEmbeddingParams{
		ID:        id,
		Embedding: &vec,
	}); err != nil {
		return fmt.Errorf("updating note embedding %d: %w", id, err)
	}
	return nil
}

// NotesWithoutEmbedding returns notes that need embedding generation.
func (s *Store) NotesWithoutEmbedding(ctx context.Context, batchSize int32) ([]EmbeddingCandidate, error) {
	rows, err := s.q.NotesWithoutEmbedding(ctx, batchSize)
	if err != nil {
		return nil, fmt.Errorf("listing notes without embedding: %w", err)
	}
	candidates := make([]EmbeddingCandidate, len(rows))
	for i, r := range rows {
		candidates[i] = EmbeddingCandidate{
			ID:          r.ID,
			FilePath:    r.FilePath,
			Title:       r.Title,
			ContentText: r.ContentText,
		}
	}
	return candidates, nil
}

// SearchBySimilarity performs semantic search using cosine similarity.
func (s *Store) SearchBySimilarity(ctx context.Context, queryVec pgvector.Vector, limit int) ([]SimilarityResult, error) {
	rows, err := s.q.SearchNotesBySimilarity(ctx, db.SearchNotesBySimilarityParams{
		QueryEmbedding: queryVec,
		MaxResults:     int32(limit), // #nosec G115 -- bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("semantic search notes: %w", err)
	}
	results := make([]SimilarityResult, len(rows))
	for i := range rows {
		r := &rows[i]
		n := Note{
			ID:          r.ID,
			FilePath:    r.FilePath,
			Title:       r.Title,
			Type:        r.Type,
			Source:      r.Source,
			Context:     r.Context,
			Maturity:    &r.Maturity,
			Difficulty:  r.Difficulty,
			Book:        r.Book,
			Chapter:     r.Chapter,
			ContentText: r.ContentText,
			SyncedAt:    &r.SyncedAt,
		}
		if r.RawTags != nil {
			_ = json.Unmarshal(r.RawTags, &n.Tags) // best-effort
		}
		if n.Tags == nil {
			n.Tags = []string{}
		}
		results[i] = SimilarityResult{Note: n, Similarity: r.Similarity}
	}
	return results, nil
}

// toNoteFromTypeRow converts a NotesByTypeAndContextRow to a domain Note.
func toNoteFromTypeRow(r *db.NotesByTypeAndContextRow) Note {
	n := Note{
		ID:          r.ID,
		FilePath:    r.FilePath,
		Title:       r.Title,
		Type:        r.Type,
		Source:      r.Source,
		Context:     r.Context,
		Maturity:    &r.Maturity,
		Difficulty:  r.Difficulty,
		Book:        r.Book,
		Chapter:     r.Chapter,
		ContentText: r.ContentText,
		SyncedAt:    &r.SyncedAt,
	}
	if r.RawTags != nil {
		_ = json.Unmarshal(r.RawTags, &n.Tags) // best-effort
	}
	if n.Tags == nil {
		n.Tags = []string{}
	}
	return n
}
