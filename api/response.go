package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// writeJSON writes a JSON response with the given status code.
// Note: If encoding fails after WriteHeader is called, there's no way to
// notify the client since the status code is already sent. The error is
// logged for debugging but doesn't affect the response.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Log encoding error for debugging - can't change response after WriteHeader
		slog.Error("failed to encode JSON response", "error", err)
	}
}

// ErrorResponse represents a JSON error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, err string, message string) {
	writeJSON(w, status, ErrorResponse{Error: err, Message: message})
}
