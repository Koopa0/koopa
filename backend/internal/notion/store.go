package notion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/koopa0/blog-backend/internal/db"
)

// Store manages notion_sources in the database.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a Store that uses the given transaction.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// Sources returns all registered Notion sources.
func (s *Store) Sources(ctx context.Context) ([]Source, error) {
	rows, err := s.q.Sources(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing notion sources: %w", err)
	}
	sources := make([]Source, len(rows))
	for i, r := range rows {
		sources[i] = dbToSource(r)
	}
	return sources, nil
}

// Source returns a single source by ID.
func (s *Store) Source(ctx context.Context, id uuid.UUID) (*Source, error) {
	row, err := s.q.SourceByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying notion source %s: %w", id, err)
	}
	src := dbToSource(row)
	return &src, nil
}

// CreateSource inserts a new source. Returns ErrConflict if database_id is taken.
func (s *Store) CreateSource(ctx context.Context, p CreateSourceParams) (*Source, error) {
	row, err := s.q.CreateSource(ctx, db.CreateSourceParams{
		DatabaseID:   p.DatabaseID,
		Name:         p.Name,
		Description:  p.Description,
		SyncMode:     p.SyncMode,
		PropertyMap:  p.PropertyMap,
		PollInterval: p.PollInterval,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating notion source: %w", err)
	}
	src := dbToSource(row)
	return &src, nil
}

// UpdateSource modifies an existing source. Returns ErrNotFound if missing.
func (s *Store) UpdateSource(ctx context.Context, id uuid.UUID, p UpdateSourceParams) (*Source, error) {
	row, err := s.q.UpdateSource(ctx, db.UpdateSourceParams{
		ID:           id,
		Name:         p.Name,
		Description:  p.Description,
		SyncMode:     p.SyncMode,
		PropertyMap:  rawToBytes(p.PropertyMap),
		PollInterval: p.PollInterval,
		Enabled:      p.Enabled,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("updating notion source %s: %w", id, err)
	}
	src := dbToSource(row)
	return &src, nil
}

// DeleteSource removes a source by ID. Returns ErrNotFound if the ID does not exist.
func (s *Store) DeleteSource(ctx context.Context, id uuid.UUID) error {
	n, err := s.q.DeleteSource(ctx, id)
	if err != nil {
		return fmt.Errorf("deleting notion source %s: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ToggleEnabled flips the enabled flag. Returns ErrNotFound if missing.
func (s *Store) ToggleEnabled(ctx context.Context, id uuid.UUID) (*Source, error) {
	row, err := s.q.ToggleSourceEnabled(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("toggling notion source %s: %w", id, err)
	}
	src := dbToSource(row)
	return &src, nil
}

// UpdateLastSynced records a successful sync timestamp. No-op if the ID does not exist.
func (s *Store) UpdateLastSynced(ctx context.Context, id uuid.UUID) error {
	if err := s.q.UpdateSourceLastSynced(ctx, id); err != nil {
		return fmt.Errorf("updating last synced for notion source %s: %w", id, err)
	}
	return nil
}

// dbToSource converts the sqlc model to the domain type.
func dbToSource(r db.NotionSource) Source {
	return Source{
		ID:           r.ID,
		DatabaseID:   r.DatabaseID,
		Name:         r.Name,
		Description:  r.Description,
		SyncMode:     r.SyncMode,
		PropertyMap:  json.RawMessage(r.PropertyMap),
		PollInterval: r.PollInterval,
		Enabled:      r.Enabled,
		LastSyncedAt: r.LastSyncedAt,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}
}

// rawToBytes converts *json.RawMessage to json.RawMessage ([]byte) for sqlc.
func rawToBytes(p *json.RawMessage) json.RawMessage {
	if p == nil {
		return nil
	}
	return *p
}
