package api

import (
	"encoding/json"
	"net/http"
)

// writeJSON writes a JSON response with the given status code.
// Note: If encoding fails after WriteHeader is called, there's no way to
// notify the client since the status code is already sent. The error is
// silently ignored as this is a rare edge case (e.g., unencodable types).
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Ignore encoding error - WriteHeader already called, can't change response
	_ = json.NewEncoder(w).Encode(data)
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
