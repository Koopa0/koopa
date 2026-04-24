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
// koopa.actor. Without set_config, current_actor() falls back to the
// literal 'system' (registered in BuiltinAgents as a safety net, but its
// appearance in activity_events is a red flag indicating the Go path
// forgot to set actor).
//
// Scope must be transaction-local, not session-local: pgxpool reuses
// connections across callers, so a session-level GUC would leak one
// caller's identity into every subsequent caller's writes. set_config
// with is_local=true matches SET LOCAL — the value is discarded on
// COMMIT or ROLLBACK.
//
// Empty caller identity is a programming error — this helper fails loud
// rather than silently falling through to the 'system' fallback.
func (s *Server) withActorTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	actor := s.callerIdentity(ctx)
	if actor == "" {
		return fmt.Errorf("refusing to open actor-scoped tx with empty caller identity")
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
