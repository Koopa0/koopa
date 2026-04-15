package note

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles database operations for agent notes.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// Create inserts a new agent note.
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Note, error) {
	var metaBytes json.RawMessage
	if p.Metadata != nil {
		b, err := json.Marshal(p.Metadata)
		if err != nil {
			return nil, fmt.Errorf("marshaling metadata: %w", err)
		}
		metaBytes = b
	}

	r, err := s.q.CreateAgentNote(ctx, db.CreateAgentNoteParams{
		Kind:      db.AgentNoteKind(p.Kind),
		Author:    p.Author,
		Content:   p.Content,
		Metadata:  metaBytes,
		EntryDate: p.EntryDate,
	})
	if err != nil {
		return nil, fmt.Errorf("creating agent note: %w", err)
	}
	return rowToNote(&r)
}

// NoteByID returns a single agent note by ID.
func (s *Store) NoteByID(ctx context.Context, id int64) (*Note, error) {
	r, err := s.q.AgentNoteByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying agent note %d: %w", id, err)
	}
	return rowToNote(&r)
}

// NotesInRange returns notes within a date range, optionally filtered by kind and source.
func (s *Store) NotesInRange(ctx context.Context, start, end time.Time, kindFilter *Kind, sourceFilter *string) ([]Note, error) {
	kindArg := db.NullAgentNoteKind{}
	if kindFilter != nil {
		kindArg.AgentNoteKind = db.AgentNoteKind(*kindFilter)
		kindArg.Valid = true
	}
	rows, err := s.q.AgentNotesByDateRange(ctx, db.AgentNotesByDateRangeParams{
		StartDate: start,
		EndDate:   end,
		Kind:      kindArg,
		Author:    sourceFilter,
	})
	if err != nil {
		return nil, fmt.Errorf("listing agent notes in range: %w", err)
	}
	notes := make([]Note, 0, len(rows))
	for i := range rows {
		n, err := rowToNote(&rows[i])
		if err != nil {
			return nil, err
		}
		notes = append(notes, *n)
	}
	return notes, nil
}

// LatestByKind returns the most recent note of a specific kind.
func (s *Store) LatestByKind(ctx context.Context, kind Kind) (*Note, error) {
	r, err := s.q.LatestAgentNoteByKind(ctx, db.AgentNoteKind(kind))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying latest %s note: %w", kind, err)
	}
	return rowToNote(&r)
}

// ReflectionsForDate returns reflection notes for a specific date.
func (s *Store) ReflectionsForDate(ctx context.Context, date time.Time) ([]Note, error) {
	rows, err := s.q.ReflectionNotesForDate(ctx, date)
	if err != nil {
		return nil, fmt.Errorf("listing reflection notes for %s: %w", date.Format(time.DateOnly), err)
	}
	notes := make([]Note, 0, len(rows))
	for i := range rows {
		n, err := rowToNote(&rows[i])
		if err != nil {
			return nil, err
		}
		notes = append(notes, *n)
	}
	return notes, nil
}

func rowToNote(r *db.AgentNote) (*Note, error) {
	var meta map[string]any
	if len(r.Metadata) > 0 {
		if err := json.Unmarshal(r.Metadata, &meta); err != nil {
			return nil, fmt.Errorf("unmarshaling agent note %d metadata: %w", r.ID, err)
		}
	}
	return &Note{
		ID:        r.ID,
		Kind:      Kind(r.Kind),
		Author:    r.Author,
		Content:   r.Content,
		Metadata:  meta,
		EntryDate: r.EntryDate,
		CreatedAt: r.CreatedAt,
	}, nil
}
