package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/koopa0/blog-backend/internal/db"
)

// Store handles database operations for session notes.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// CreateNote inserts a new session note.
func (s *Store) CreateNote(ctx context.Context, p CreateParams) (*Note, error) {
	row, err := s.q.CreateNote(ctx, db.CreateNoteParams{
		NoteDate: p.NoteDate,
		NoteType: p.NoteType,
		Source:   p.Source,
		Content:  p.Content,
		Metadata: p.Metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("creating session note: %w", err)
	}
	n := rowToNote(row)
	return &n, nil
}

// NotesByDate returns session notes within a date range, optionally filtered by type.
func (s *Store) NotesByDate(ctx context.Context, startDate, endDate time.Time, noteType *string) ([]Note, error) {
	rows, err := s.q.NotesByDate(ctx, db.NotesByDateParams{
		StartDate: startDate,
		EndDate:   endDate,
		NoteType:  noteType,
	})
	if err != nil {
		return nil, fmt.Errorf("listing session notes: %w", err)
	}
	notes := make([]Note, len(rows))
	for i, r := range rows {
		notes[i] = rowToNote(r)
	}
	return notes, nil
}

// LatestNoteByType returns the most recent note of the given type.
// Returns ErrNotFound when no note exists.
func (s *Store) LatestNoteByType(ctx context.Context, noteType string) (*Note, error) {
	row, err := s.q.LatestNoteByType(ctx, noteType)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying latest %s note: %w", noteType, err)
	}
	n := rowToNote(row)
	return &n, nil
}

// MetricsHistory returns metrics notes since the given date.
func (s *Store) MetricsHistory(ctx context.Context, sinceDate time.Time) ([]Note, error) {
	rows, err := s.q.MetricsHistory(ctx, sinceDate)
	if err != nil {
		return nil, fmt.Errorf("querying metrics history: %w", err)
	}
	notes := make([]Note, len(rows))
	for i, r := range rows {
		notes[i] = rowToNote(r)
	}
	return notes, nil
}

// NoteByID returns a single session note by ID.
// Returns ErrNotFound when no note exists.
func (s *Store) NoteByID(ctx context.Context, id int64) (*Note, error) {
	row, err := s.q.NoteByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying session note %d: %w", id, err)
	}
	n := rowToNote(row)
	return &n, nil
}

// InsightsByStatus returns insight notes filtered by optional status and project.
func (s *Store) InsightsByStatus(ctx context.Context, status, project *string, limit int32) ([]Note, error) {
	rows, err := s.q.InsightsByStatus(ctx, db.InsightsByStatusParams{
		Status:   status,
		Project:  project,
		LimitVal: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying insights: %w", err)
	}
	notes := make([]Note, len(rows))
	for i, r := range rows {
		notes[i] = rowToNote(r)
	}
	return notes, nil
}

// CountInsightsByStatus returns the count of insight notes with the given status.
func (s *Store) CountInsightsByStatus(ctx context.Context, status *string) (int64, error) {
	n, err := s.q.CountInsightsByStatus(ctx, status)
	if err != nil {
		return 0, fmt.Errorf("counting insights: %w", err)
	}
	return n, nil
}

// UpdateNoteMetadata updates a note's metadata.
func (s *Store) UpdateNoteMetadata(ctx context.Context, p UpdateMetadataParams) (*Note, error) {
	row, err := s.q.UpdateNoteMetadata(ctx, db.UpdateNoteMetadataParams{
		ID:       p.ID,
		Metadata: p.Metadata,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating session note %d metadata: %w", p.ID, err)
	}
	n := rowToNote(row)
	return &n, nil
}

// ArchiveStaleInsights sets verified/invalidated insights older than cutoff to archived.
func (s *Store) ArchiveStaleInsights(ctx context.Context, cutoff time.Time) (int64, error) {
	n, err := s.q.ArchiveStaleInsights(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("archiving stale insights: %w", err)
	}
	return n, nil
}

// DeleteOldNotes deletes session notes with note_date before cutoff.
func (s *Store) DeleteOldNotes(ctx context.Context, cutoff time.Time) (int64, error) {
	n, err := s.q.DeleteOldNotes(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("deleting old session notes: %w", err)
	}
	return n, nil
}

func rowToNote(r db.SessionNote) Note {
	return Note{
		ID:        r.ID,
		NoteDate:  r.NoteDate,
		NoteType:  r.NoteType,
		Source:    r.Source,
		Content:   r.Content,
		Metadata:  r.Metadata,
		CreatedAt: r.CreatedAt,
	}
}
