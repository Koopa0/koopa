package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
)

// Error is the JSON body for error responses.
type Error struct {
	Status  int    `json:"status"`
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
//
// SECURITY: The message parameter MUST be a static, user-friendly string.
// NEVER pass err.Error() or any dynamic error content — this prevents
// database schema details, file paths, and internal state from leaking
// to clients (CWE-209). Log the full error server-side instead.
//
// SECURITY: The status parameter MUST be a static http.Status* constant.
// NEVER pass a dynamic status code from a variable or third-party library.
func WriteError(w http.ResponseWriter, status int, code, message string, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(envelope{Error: &Error{Status: status, Code: code, Message: message}}); err != nil {
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("encoding JSON error response", "error", err)
	}
}

// requireUserID extracts the user ID from the request context.
// Returns the user ID and true on success.
// On failure, writes a 403 error response and returns empty string and false.
func requireUserID(w http.ResponseWriter, r *http.Request, logger *slog.Logger) (string, bool) {
	userID, ok := userIDFromContext(r.Context())
	if !ok || userID == "" {
		WriteError(w, http.StatusForbidden, "forbidden", "user identity required", logger)
		return "", false
	}
	return userID, true
}

// parseIntParam parses an integer query parameter with a default value.
// Returns defaultVal if the parameter is missing, not a valid integer, or negative.
func parseIntParam(r *http.Request, key string, defaultVal int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return defaultVal
	}
	return n
}
