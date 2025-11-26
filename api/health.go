package api

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/koopa-cli/internal/log"
)

// HealthHandler handles health check endpoints.
type HealthHandler struct {
	pool   *pgxpool.Pool
	logger log.Logger
}

// NewHealthHandler creates a new health handler.
// pool is the database connection pool used for readiness checks.
func NewHealthHandler(pool *pgxpool.Pool, logger log.Logger) *HealthHandler {
	return &HealthHandler{pool: pool, logger: logger}
}

// RegisterRoutes registers health routes on the given mux.
func (h *HealthHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.liveness)
	mux.HandleFunc("GET /ready", h.readiness)
}

// liveness is a liveness probe endpoint.
// Returns 200 OK if the process is alive.
func (h *HealthHandler) liveness(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// readiness is a readiness probe endpoint.
// Returns 200 OK if all dependencies are ready.
// Performs actual health check by pinging the database.
func (h *HealthHandler) readiness(w http.ResponseWriter, r *http.Request) {
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
