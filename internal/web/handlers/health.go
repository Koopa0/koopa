package handlers

import (
	"net/http"
)

// Health handles health check endpoints for Docker/Kubernetes probes.
type Health struct{}

// NewHealth creates a health check handler.
func NewHealth() *Health {
	return &Health{}
}

// RegisterRoutes registers health check routes on the given mux.
func (*Health) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", health)
	mux.HandleFunc("GET /ready", health)
}

// health is a simple health check endpoint.
// Returns 200 OK if the process is alive.
func health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
