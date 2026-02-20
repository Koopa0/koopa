package api

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

// health is a simple health check endpoint for Docker/Kubernetes probes.
// Returns 200 OK with {"status":"ok"}.
func health(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"}, nil)
}

// readiness returns pool stats alongside the health status.
// If pool is nil, it behaves identically to health.
func readiness(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if pool == nil {
			WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"}, nil)
			return
		}

		stat := pool.Stat()
		resp := map[string]any{
			"status": "ok",
			"db": map[string]any{
				"total":  stat.TotalConns(),
				"idle":   stat.IdleConns(),
				"in_use": stat.AcquiredConns(),
			},
		}
		WriteJSON(w, http.StatusOK, resp, nil)
	}
}
