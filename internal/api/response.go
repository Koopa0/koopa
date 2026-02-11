package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// Error is the JSON body for error responses.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// envelope wraps all API responses in a consistent structure.
// Success: {"data": <payload>}
// Error:   {"error": {"code": "...", "message": "..."}}
type envelope struct {
	Data  any    `json:"data,omitempty"`
	Error *Error `json:"error,omitempty"`
}

// WriteJSON writes data wrapped in an envelope as JSON.
// For nil data, writes no body (use with 204 No Content).
// If logger is nil, falls back to slog.Default().
func WriteJSON(w http.ResponseWriter, status int, data any, logger *slog.Logger) {
	if data != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(envelope{Data: data}); err != nil {
			if logger == nil {
				logger = slog.Default()
			}
			logger.Error("encoding JSON response", "error", err)
		}
	} else {
		w.WriteHeader(status)
	}
}

// WriteError writes a JSON error response wrapped in an envelope.
// If logger is nil, falls back to slog.Default().
func WriteError(w http.ResponseWriter, status int, code, message string, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(envelope{Error: &Error{Code: code, Message: message}}); err != nil {
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("encoding JSON error response", "error", err)
	}
}
