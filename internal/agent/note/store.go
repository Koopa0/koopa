package note

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa/internal/db"
)

// Store handles database operations for agent notes.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a Store bound to tx for all queries. Used by callers
// composing multi-store transactions — typically via api.ActorMiddleware
// (HTTP) or mcp.Server.withActorTx (MCP). The tx carries koopa.actor
// so audit triggers attribute mutations correctly.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
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
		CreatedBy: p.CreatedBy,
		Content:   p.Content,
		Metadata:  metaBytes,
		EntryDate: p.EntryDate,
	})
	if err != nil {
		return nil, fmt.Errorf("creating agent note: %w", err)
	}
	return rowToNote(r.ID, r.Kind, r.CreatedBy, r.Content, r.Metadata, r.EntryDate, r.CreatedAt)
}

// NoteByID returns a single agent note by ID.
func (s *Store) NoteByID(ctx context.Context, id uuid.UUID) (*Note, error) {
	r, err := s.q.AgentNoteByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying agent note %s: %w", id, err)
	}
	return rowToNote(r.ID, r.Kind, r.CreatedBy, r.Content, r.Metadata, r.EntryDate, r.CreatedAt)
}

// NotesInRange returns notes within a date range, optionally filtered by kind
// and created_by.
func (s *Store) NotesInRange(ctx context.Context, start, end time.Time, kindFilter *Kind, createdByFilter *string) ([]Note, error) {
	kindArg := db.NullAgentNoteKind{}
	if kindFilter != nil {
		kindArg.AgentNoteKind = db.AgentNoteKind(*kindFilter)
		kindArg.Valid = true
	}
	rows, err := s.q.AgentNotesByDateRange(ctx, db.AgentNotesByDateRangeParams{
		StartDate: start,
		EndDate:   end,
		Kind:      kindArg,
		CreatedBy: createdByFilter,
	})
	if err != nil {
		return nil, fmt.Errorf("listing agent notes in range: %w", err)
	}
	notes := make([]Note, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		n, err := rowToNote(r.ID, r.Kind, r.CreatedBy, r.Content, r.Metadata, r.EntryDate, r.CreatedAt)
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
	return rowToNote(r.ID, r.Kind, r.CreatedBy, r.Content, r.Metadata, r.EntryDate, r.CreatedAt)
}

// Search performs full-text search over agent_notes within a date range,
// ranked by ts_rank × recency decay. Returns notes ordered by score DESC
// (best-matching recent notes first). Filter args kind and createdBy
// are optional — pass nil to skip.
func (s *Store) Search(ctx context.Context, query string, start, end time.Time, kindFilter *Kind, createdByFilter *string, limit int) ([]Note, error) {
	kindArg := db.NullAgentNoteKind{}
	if kindFilter != nil {
		kindArg.AgentNoteKind = db.AgentNoteKind(*kindFilter)
		kindArg.Valid = true
	}
	rows, err := s.q.SearchAgentNotes(ctx, db.SearchAgentNotesParams{
		Query:     query,
		StartDate: start,
		EndDate:   end,
		Kind:      kindArg,
		CreatedBy: createdByFilter,
		RowLimit:  int32(limit), // #nosec G115 -- caller bounds limit via clamp
	})
	if err != nil {
		return nil, fmt.Errorf("searching agent notes: %w", err)
	}
	notes := make([]Note, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		n, err := rowToNote(r.ID, r.Kind, r.CreatedBy, r.Content, r.Metadata, r.EntryDate, r.CreatedAt)
		if err != nil {
			return nil, err
		}
		notes = append(notes, *n)
	}
	return notes, nil
}

// ReflectionsForDate returns reflection notes for a specific date.
func (s *Store) ReflectionsForDate(ctx context.Context, date time.Time) ([]Note, error) {
	rows, err := s.q.ReflectionNotesForDate(ctx, date)
	if err != nil {
		return nil, fmt.Errorf("listing reflection notes for %s: %w", date.Format(time.DateOnly), err)
	}
	notes := make([]Note, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		n, err := rowToNote(r.ID, r.Kind, r.CreatedBy, r.Content, r.Metadata, r.EntryDate, r.CreatedAt)
		if err != nil {
			return nil, err
		}
		notes = append(notes, *n)
	}
	return notes, nil
}

// rowToNote builds a Note from the common field set every sqlc-generated
// agent_notes Row exposes. Per-query Row types exist because agent_notes
// has a generated search_vector column that no query selects, so sqlc
// emits a distinct Row per query. Rather than maintain six overloads we
// accept the fields directly — callers destructure their Row at the call
// site.
func rowToNote(id uuid.UUID, kind db.AgentNoteKind, createdBy, content string, metadata json.RawMessage, entryDate, createdAt time.Time) (*Note, error) {
	var meta map[string]any
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &meta); err != nil {
			return nil, fmt.Errorf("unmarshaling agent note %s metadata: %w", id, err)
		}
	}
	return &Note{
		ID:        id,
		Kind:      Kind(kind),
		CreatedBy: createdBy,
		Content:   content,
		Metadata:  meta,
		EntryDate: entryDate,
		CreatedAt: createdAt,
	}, nil
}
