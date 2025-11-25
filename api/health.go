package api

import (
	"net/http"

	"github.com/koopa0/koopa-cli/internal/session"
)

// HealthHandler handles health check endpoints.
type HealthHandler struct {
	store *session.Store
}

// NewHealthHandler creates a new health handler.
func NewHealthHandler(store *session.Store) *HealthHandler {
	return &HealthHandler{store: store}
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
func (h *HealthHandler) readiness(w http.ResponseWriter, _ *http.Request) {
	if h.store == nil {
		http.Error(w, "session store not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}
