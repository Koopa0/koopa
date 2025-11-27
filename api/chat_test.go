package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChatHandler_InvalidInput tests SSE handler with invalid input scenarios.
func TestChatHandler_InvalidInput(t *testing.T) {
	t.Parallel()

	logger := log.NewNop()
	// ChatHandler with nil flow - endpoints won't be registered but we can test
	// handler methods directly
	h := NewChatHandler(nil, logger)

	t.Run("missing session ID", func(t *testing.T) {
		t.Parallel()

		body, _ := json.Marshal(chat.Input{
			Query:     "test query",
			SessionID: "",
		})

		req := httptest.NewRequest(http.MethodPost, "/api/chat/stream", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.handleStream(w, req)

		// SSE should return error event
		assert.Equal(t, http.StatusOK, w.Code) // SSE always returns 200 first
		assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
		assert.Contains(t, w.Body.String(), "MISSING_SESSION_ID")
		assert.Contains(t, w.Body.String(), "event: error")
	})

	t.Run("missing query", func(t *testing.T) {
		t.Parallel()

		body, _ := json.Marshal(chat.Input{
			Query:     "",
			SessionID: "test-session-id",
		})

		req := httptest.NewRequest(http.MethodPost, "/api/chat/stream", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.handleStream(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "MISSING_QUERY")
		assert.Contains(t, w.Body.String(), "event: error")
	})

	t.Run("invalid JSON body", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "/api/chat/stream", strings.NewReader("not json"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.handleStream(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "INVALID_REQUEST")
		assert.Contains(t, w.Body.String(), "event: error")
	})
}

// TestChatHandler_SSEFormat tests that SSE events are properly formatted.
func TestChatHandler_SSEFormat(t *testing.T) {
	t.Parallel()

	logger := log.NewNop()
	h := NewChatHandler(nil, logger)

	t.Run("error event format", func(t *testing.T) {
		t.Parallel()

		body, _ := json.Marshal(chat.Input{
			Query:     "",
			SessionID: "test",
		})

		req := httptest.NewRequest(http.MethodPost, "/api/chat/stream", bytes.NewReader(body))
		w := httptest.NewRecorder()

		h.handleStream(w, req)

		// Verify SSE format: "event: <type>\ndata: <json>\n\n"
		lines := strings.Split(w.Body.String(), "\n")
		require.GreaterOrEqual(t, len(lines), 2)

		var foundEvent, foundData bool
		for _, line := range lines {
			if strings.HasPrefix(line, "event: error") {
				foundEvent = true
			}
			if strings.HasPrefix(line, "data: ") {
				foundData = true
				// Verify data is valid JSON
				jsonData := strings.TrimPrefix(line, "data: ")
				var parsed map[string]any
				err := json.Unmarshal([]byte(jsonData), &parsed)
				assert.NoError(t, err, "SSE data should be valid JSON")
				assert.Contains(t, parsed, "code")
				assert.Contains(t, parsed, "message")
			}
		}

		assert.True(t, foundEvent, "should have 'event: error' line")
		assert.True(t, foundData, "should have 'data: ' line")
	})
}

// TestChatHandler_RegisterRoutes tests route registration.
func TestChatHandler_RegisterRoutes(t *testing.T) {
	t.Parallel()

	logger := log.NewNop()

	t.Run("nil flow does not register routes", func(t *testing.T) {
		t.Parallel()

		h := NewChatHandler(nil, logger)
		mux := http.NewServeMux()
		h.RegisterRoutes(mux)

		// With nil flow, routes should not be registered
		// Making a request should return 404
		req := httptest.NewRequest(http.MethodPost, "/api/chat", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestEscapeJSON tests the JSON escaping function.
func TestEscapeJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple string", "hello", "hello"},
		{"with quotes", `say "hello"`, `say \"hello\"`},
		{"with backslash", `path\to\file`, `path\\to\\file`},
		{"with newline", "line1\nline2", `line1\nline2`},
		{"with tab", "col1\tcol2", `col1\tcol2`},
		{"with carriage return", "text\rmore", `text\rmore`},
		{"control character", "text\x01here", `text\u0001here`},
		{"empty string", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := escapeJSON(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
