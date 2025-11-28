package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// writeJSON writes a JSON response with the given status code.
// Encoding errors are logged but cannot change the response (header already sent).
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Log for observability; can't change response since header is already sent
		slog.Error("failed to encode JSON response", "error", err)
	}
}
