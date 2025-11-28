package api

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/koopa-cli/internal/log"
)

// Health handles health check endpoints.
type Health struct {
	pool   *pgxpool.Pool
	logger log.Logger
}

// NewHealth creates a new health handler.
// pool is the database connection pool used for readiness checks.
func NewHealth(pool *pgxpool.Pool, logger log.Logger) *Health {
	return &Health{pool: pool, logger: logger}
}

// RegisterRoutes registers health routes on the given mux.
func (h *Health) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.liveness)
	mux.HandleFunc("GET /ready", h.readiness)
}

// liveness is a liveness probe endpoint.
// Returns 200 OK if the process is alive.
func (*Health) liveness(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// readiness is a readiness probe endpoint.
// Returns 200 OK if all dependencies are ready.
// Performs actual health check by pinging the database.
//
// Note: This uses the request context without an explicit timeout.
// In production, Kubernetes probes have their own timeout (default 1s),
// so a hung DB ping will be terminated by the probe timeout.
// If deterministic local behavior is needed, wrap with context.WithTimeout.
func (h *Health) readiness(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		http.Error(w, "database pool not configured", http.StatusServiceUnavailable)
		return
	}
	if err := h.pool.Ping(r.Context()); err != nil {
		h.logger.Error("readiness check failed", "error", err)
		http.Error(w, "database not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}
