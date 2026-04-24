// middleware.go holds ActorMiddleware — the per-request tx wrapper
// that binds koopa.actor and stashes the tx in context via
// TxFromContext. Handlers on the adminMid chain (cmd/app/routes.go)
// MUST read the tx and call store.WithTx(tx).Mutation to propagate
// the actor binding to the audit trigger. A handler that forgets
// silently falls through to the 'system' audit-actor fallback — the
// hook doesn't catch this, only code review does.

package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// txKey is an unexported context key type for the request-scoped pgx.Tx.
// Typed zero-value struct per .claude/rules/concurrency.md context rules.
type txKey struct{}

// actorKey is an unexported context key type for the admin actor name
// bound by ActorMiddleware. Same scheme as txKey — caller extracts via
// ActorFromContext to avoid re-hardcoding "human" at each stamp site.
type actorKey struct{}

// ActorMiddleware opens a transaction per admin request, binds koopa.actor
// via SELECT set_config('koopa.actor', $1, true) (transaction-local), and
// injects both the tx and the actor name into the request context.
// Handlers extract them via TxFromContext / ActorFromContext: the tx
// flows to store.WithTx(tx) so every mutation runs inside the actor-bound
// transaction, and the actor name is the single source of truth for
// handler-level stamp fields (curated_by, created_by, selected_by).
//
// The actor value flows: cmd/app/main.go literal → ActorMiddleware arg
// → context → handler. Handlers MUST NOT hardcode "human" or read a
// stamp name from claims directly — if they do, main's literal and the
// handler's literal can diverge silently (each admin mutation's audit
// row and FK stamp end up with different identities). Multi-admin
// support becomes "change the argument main passes to ActorMiddleware
// (e.g. resolve from auth.ClaimsFromContext)"; handlers stay untouched.
//
// Mirrors the MCP-side reference at internal/mcp/tx.go (withActorTx):
//  1. pool.Begin(ctx)
//  2. SELECT set_config('koopa.actor', <actor>, true)  // true = tx-local
//  3. next.ServeHTTP with tx-carrying context
//  4. response status in [200, 400) -> Commit; otherwise defer Rollback
//
// bind failure returns 500 before any handler runs (lines below).
// BUT: if an admin handler correctly receives the bound tx and then
// forgets to call store.WithTx(tx), the store falls back to a fresh
// pool connection whose session has NO koopa.actor set. The audit
// trigger's current_actor() falls through to the literal 'system' agent.
// This is documented as a handler-wiring bug and caught by integration
// test TestActorProvenance_AdminMutation, which asserts every admin
// mutation lands an activity_events row with actor != 'system'.
//
// Why not promote current_actor() to RAISE EXCEPTION at SQL level:
// pg_cron jobs legitimately write without Go middleware, and their
// audit rows must land with actor='system'. The Go paths (HTTP + MCP)
// are bounded — a handful of handlers — so integration-test detection
// is sufficient for them.
//
// Actor scope MUST be transaction-local (set_config is_local=true), not
// session-local: pgxpool reuses connections across callers, so a session
// GUC would leak one caller's identity into the next caller's writes.
func ActorMiddleware(pool *pgxpool.Pool, actor string, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			tx, err := pool.Begin(ctx)
			if err != nil {
				logger.Error("actor middleware: begin tx",
					"error", err,
					"method", r.Method,
					"path", r.URL.Path,
				)
				Error(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
				return
			}
			defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit; rollback on error path

			// set_config($1, $2, true) is the parameter-bindable equivalent
			// of SET LOCAL koopa.actor = '<actor>'. The literal SET syntax
			// does not accept $N placeholders.
			if _, err := tx.Exec(ctx, "SELECT set_config('koopa.actor', $1, true)", actor); err != nil {
				logger.Error("actor middleware: bind koopa.actor",
					"error", err,
					"actor", actor,
					"method", r.Method,
					"path", r.URL.Path,
				)
				Error(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
				return
			}

			sw := &statusCapturingWriter{ResponseWriter: w}
			ctxWithTx := context.WithValue(ctx, txKey{}, tx)
			ctxWithActor := context.WithValue(ctxWithTx, actorKey{}, actor)
			next.ServeHTTP(sw, r.WithContext(ctxWithActor))

			// Commit on 2xx/3xx; defer handles rollback for 4xx/5xx and
			// for handlers that never called WriteHeader (status stays 0,
			// which we treat as "no response written" -> rollback, since
			// a missing status is itself a handler bug).
			if sw.status >= 200 && sw.status < 400 {
				if err := tx.Commit(ctx); err != nil {
					// Body is already on the wire; the client saw success
					// but the write rolled back. Emit a stable event key
					// so alerts + dashboards can grep for this specific
					// data-integrity case without pattern-matching the
					// free-form message (per .claude/rules/go-slog.md).
					logger.Error("actor middleware: commit tx",
						"event", "tx_commit_failed",
						"error", err,
						"status", sw.status,
						"method", r.Method,
						"path", r.URL.Path,
					)
				}
			}
		})
	}
}

// TxFromContext returns the request-scoped pgx.Tx injected by
// ActorMiddleware. Returns (nil, false) when the middleware is not in
// play (e.g. non-admin routes that do not mutate audited tables).
//
// Handlers wrapped by ActorMiddleware should expect ok=true. If ok=false
// in an admin handler, that is a wiring bug — log and fall back to the
// bare store (audit trigger will record 'system' actor, and
// TestActorProvenance_AdminMutation will catch it in CI). Production
// traffic is not blocked, but the broken path is made visible in tests
// rather than silently degrading forever.
func TxFromContext(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(txKey{}).(pgx.Tx)
	return tx, ok
}

// ActorFromContext returns the admin actor name injected by
// ActorMiddleware. Handlers that stamp a caller identity field
// (curated_by, created_by, selected_by) MUST read from here instead of
// hardcoding a literal — see ActorMiddleware's doc for the single-
// source-of-truth rationale.
//
// Returns ("", false) when the middleware is not in play (tests,
// non-admin routes). Callers decide the fallback appropriate to their
// context; for admin writes the convention is "human".
func ActorFromContext(ctx context.Context) (string, bool) {
	actor, ok := ctx.Value(actorKey{}).(string)
	return actor, ok
}

// statusCapturingWriter wraps http.ResponseWriter and records the first
// status code written. Subsequent WriteHeader calls are ignored
// (preserving net/http's single-WriteHeader semantics). A Write without a
// prior WriteHeader implicitly records 200, matching net/http behavior.
//
// Unwrap exposes the underlying writer so Go 1.20+ response writer
// interface discovery (http.Flusher, http.Hijacker, etc.) still works.
type statusCapturingWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// WriteHeader records the first status code and forwards the call. Later
// calls are swallowed (net/http would log "superfluous WriteHeader call").
func (sw *statusCapturingWriter) WriteHeader(code int) {
	if sw.wroteHeader {
		return
	}
	sw.status = code
	sw.wroteHeader = true
	sw.ResponseWriter.WriteHeader(code)
}

// Write captures an implicit 200 on the first call if WriteHeader was not
// called first, matching net/http's default behavior.
func (sw *statusCapturingWriter) Write(b []byte) (int, error) {
	if !sw.wroteHeader {
		sw.status = http.StatusOK
		sw.wroteHeader = true
	}
	return sw.ResponseWriter.Write(b)
}

// Unwrap returns the underlying ResponseWriter so optional interfaces
// (http.Flusher, http.Hijacker, http.Pusher) remain accessible via
// http.ResponseController.
func (sw *statusCapturingWriter) Unwrap() http.ResponseWriter {
	return sw.ResponseWriter
}
