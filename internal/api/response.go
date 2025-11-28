package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
)

// writeJSON writes a JSON response with the given status code.
// Uses buffer-first strategy to ensure headers are only sent after successful encoding.
// This allows returning a proper 500 error if JSON encoding fails.
func writeJSON(w http.ResponseWriter, status int, data any) {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(data); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.Header().Set("X-Content-Type-Options", "nosniff") // Prevent MIME type sniffing attacks
	w.WriteHeader(status)
	if _, err := w.Write(buf.Bytes()); err != nil {
		// Log at debug level - client disconnects are common and expected
		slog.Debug("failed to write response body", "error", err)
	}
}
