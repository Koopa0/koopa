// Copyright 2026 Koopa. All rights reserved.

// tx.go holds the one helper that binds koopa.actor to a pgx
// transaction's lifetime. Every MCP handler that mutates a table
// covered by an audit_* trigger goes through withActorTx so the trigger
// sees the caller's agent name via current_actor().

package mcp

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// withActorTx opens a transaction, binds koopa.actor to the current caller
// identity for its scope, then runs fn. Commits on nil return; rolls back
// otherwise. Every write path that hits a table covered by an audit_*
// trigger MUST go through this helper — the triggers insert into
// activity_events with current_actor() as the actor, which reads from
// koopa.actor. This path always sets a real actor; the trigger's only
// fallback (koopa.actor unset, e.g. a manual DB op) attributes to the owner
// ('human') — there is no synthetic 'system' agent.
//
// Scope must be transaction-local, not session-local: pgxpool reuses
// connections across callers, so a session-level GUC would leak one
// caller's identity into every subsequent caller's writes. set_config
// with is_local=true matches SET LOCAL — the value is discarded on
// COMMIT or ROLLBACK.
//
// A missing caller identity is refused here: a write tool MUST be called with
// an `as` field (or a pinned KOOPA_MCP_CALLER_AGENT). There is no `unknown`
// fallback — every audited write carries a real, registered agent.
func (s *Server) withActorTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	actor := s.callerIdentity(ctx)
	if actor == "" {
		return fmt.Errorf("missing caller identity: pass an `as` field naming a registered agent (every write must declare its actor)")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	// set_config($1, $2, true) is the parameter-bindable equivalent of
	// SET LOCAL koopa.actor = '<actor>'. The literal SET syntax does not
	// accept $N placeholders.
	if _, err := tx.Exec(ctx, "SELECT set_config('koopa.actor', $1, true)", actor); err != nil {
		return fmt.Errorf("binding koopa.actor: %w", err)
	}

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}
