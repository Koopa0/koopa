package agent

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store is the DB-side projection layer for the agents table. It is not a
// store in the full feature-package sense — there is no Go-owned Agent CRUD
// surface, because the Go registry is the source of truth. Store only
// provides the primitives SyncToTable needs: list current rows and
// upsert / retire entries.
type Store struct {
	q *db.Queries
}

// NewStore constructs a Store bound to a database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// List returns every row currently in the agents table, ordered by name.
func (s *Store) List(ctx context.Context) ([]RegistryRow, error) {
	rows, err := s.q.ListAgents(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent store: list: %w", err)
	}
	out := make([]RegistryRow, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = RegistryRow{
			Name:        Name(r.Name),
			DisplayName: r.DisplayName,
			Platform:    r.Platform,
			Description: r.Description,
			Status:      Status(r.Status),
			SyncedAt:    r.SyncedAt,
			RetiredAt:   r.RetiredAt,
		}
	}
	return out, nil
}

// Upsert writes an active agent row. If the name already exists, the row
// is updated and status is forced back to active (any previous retirement
// is cleared). Called by SyncToTable for every entry present in
// BuiltinAgents().
func (s *Store) Upsert(ctx context.Context, a *Agent) error {
	err := s.q.UpsertAgent(ctx, db.UpsertAgentParams{
		Name:        string(a.Name),
		DisplayName: a.DisplayName,
		Platform:    a.Platform,
		Description: a.Description,
	})
	if err != nil {
		return fmt.Errorf("agent store: upsert %s: %w", a.Name, err)
	}
	return nil
}

// Retire marks an existing agent row as retired. No-op if the row is
// already retired (retired_at preserved via COALESCE in the SQL). Returns
// ErrUnknownAgent wrapped if no row with that name exists.
func (s *Store) Retire(ctx context.Context, name Name) error {
	n, err := s.q.RetireAgent(ctx, string(name))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrUnknownAgent, name)
		}
		return fmt.Errorf("agent store: retire %s: %w", name, err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrUnknownAgent, name)
	}
	return nil
}
