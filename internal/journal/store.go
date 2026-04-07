package journal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles database operations for journal entries.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// Create inserts a new journal entry.
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Entry, error) {
	var meta json.RawMessage
	if p.Metadata != nil {
		var err error
		meta, err = json.Marshal(p.Metadata)
		if err != nil {
			return nil, fmt.Errorf("marshaling metadata: %w", err)
		}
	}

	row, err := s.q.CreateEntry(ctx, db.CreateEntryParams{
		Kind:      string(p.Kind),
		Source:    p.Source,
		Content:   p.Content,
		Metadata:  meta,
		EntryDate: p.EntryDate,
	})
	if err != nil {
		return nil, fmt.Errorf("creating journal entry: %w", err)
	}
	return rowToEntry(&row), nil
}

// Entry returns a single journal entry by ID.
func (s *Store) Entry(ctx context.Context, id int64) (*Entry, error) {
	row, err := s.q.EntryByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying journal entry %d: %w", id, err)
	}
	return rowToEntry(&row), nil
}

// EntriesByDateRange returns journal entries in a date range with optional filters.
func (s *Store) EntriesByDateRange(ctx context.Context, start, end time.Time, kind, source *string) ([]Entry, error) {
	rows, err := s.q.EntriesByDateRange(ctx, db.EntriesByDateRangeParams{
		StartDate: start,
		EndDate:   end,
		Kind:      kind,
		Source:    source,
	})
	if err != nil {
		return nil, fmt.Errorf("querying journal entries: %w", err)
	}
	entries := make([]Entry, len(rows))
	for i := range rows {
		entries[i] = *rowToEntry(&rows[i])
	}
	return entries, nil
}

// LatestByKind returns the most recent journal entry of a specific kind.
func (s *Store) LatestByKind(ctx context.Context, kind Kind) (*Entry, error) {
	row, err := s.q.LatestEntryByKind(ctx, string(kind))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying latest %s journal entry: %w", kind, err)
	}
	return rowToEntry(&row), nil
}

func rowToEntry(r *db.Journal) *Entry {
	e := &Entry{
		ID:        r.ID,
		Kind:      Kind(r.Kind),
		Source:    r.Source,
		Content:   r.Content,
		EntryDate: r.EntryDate,
		CreatedAt: r.CreatedAt,
	}
	if r.Metadata != nil {
		_ = json.Unmarshal(r.Metadata, &e.Metadata)
	}
	return e
}
