package api

import "net/http"

// health is a simple health check endpoint for Docker/Kubernetes probes.
// Returns 200 OK with {"status":"ok"}.
func health(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
