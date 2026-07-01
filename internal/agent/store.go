// Copyright 2026 Koopa. All rights reserved.

package agent

import (
	"context"
	"fmt"

	"github.com/Koopa0/koopa/internal/db"
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
		}
	}
	return out, nil
}

// UpsertAll writes every registered agent as active in one round trip. If a
// name already exists, its row is updated and status is forced back to
// active (any previous retirement is cleared). Called once by SyncToTable
// with the full BuiltinAgents() literal.
func (s *Store) UpsertAll(ctx context.Context, agents []Agent) error {
	names := make([]string, len(agents))
	displayNames := make([]string, len(agents))
	platforms := make([]string, len(agents))
	descriptions := make([]string, len(agents))
	for i := range agents {
		names[i] = string(agents[i].Name)
		displayNames[i] = agents[i].DisplayName
		platforms[i] = agents[i].Platform
		descriptions[i] = agents[i].Description
	}
	err := s.q.UpsertAgents(ctx, db.UpsertAgentsParams{
		Names:        names,
		DisplayNames: displayNames,
		Platforms:    platforms,
		Descriptions: descriptions,
	})
	if err != nil {
		return fmt.Errorf("agent store: batch upsert: %w", err)
	}
	return nil
}

// RetireAll marks the given existing agent rows as retired in one round
// trip. No-op per row if already retired (retired_at preserved via
// COALESCE in the SQL). Returns ErrUnknownAgent wrapped if fewer rows were
// affected than names given — some name matched no row. names MUST be
// distinct: WHERE name = ANY(...) collapses a duplicate to one matched row,
// so a repeated name would undercount and spuriously trip this check.
func (s *Store) RetireAll(ctx context.Context, names []Name) error {
	rowNames := make([]string, len(names))
	for i := range names {
		rowNames[i] = string(names[i])
	}
	n, err := s.q.RetireAgents(ctx, rowNames)
	if err != nil {
		return fmt.Errorf("agent store: batch retire: %w", err)
	}
	if n != int64(len(names)) {
		return fmt.Errorf("%w: retired %d of %d requested names", ErrUnknownAgent, n, len(names))
	}
	return nil
}
