package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: For full Session handler testing with mock store, we'd need to
// refactor SessionHandler to accept an interface instead of concrete *session.Store.
// For now, we test request parsing and error handling.

func TestSessionHandler_List_Integration(t *testing.T) {
	// This is more of an integration test since we need a real store
	// For unit tests, we'd need to refactor SessionHandler to accept an interface
	t.Skip("requires mock store interface refactor")
}

func TestSessionHandler_Create_Integration(t *testing.T) {
	t.Skip("requires mock store interface refactor")
}

// TestSessionHandler_RequestParsing tests request body parsing
func TestSessionHandler_RequestParsing(t *testing.T) {
	t.Run("create session request parsing", func(t *testing.T) {
		body := `{"title": "Test", "model_name": "gemini-2.0-flash", "system_prompt": "You are helpful."}`
		var req CreateSessionRequest
		err := json.NewDecoder(strings.NewReader(body)).Decode(&req)

		require.NoError(t, err)
		assert.Equal(t, "Test", req.Title)
		assert.Equal(t, "gemini-2.0-flash", req.ModelName)
		assert.Equal(t, "You are helpful.", req.SystemPrompt)
	})

	t.Run("create session request with empty body", func(t *testing.T) {
		body := `{}`
		var req CreateSessionRequest
		err := json.NewDecoder(strings.NewReader(body)).Decode(&req)

		require.NoError(t, err)
		assert.Empty(t, req.Title)
		assert.Empty(t, req.ModelName)
		assert.Empty(t, req.SystemPrompt)
	})
}

// TestSessionHandler_NilStore tests behavior when store is nil
func TestSessionHandler_NilStore(t *testing.T) {
	handler := NewSessionHandler(nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	t.Run("list sessions with nil store panics", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
		w := httptest.NewRecorder()

		// This will panic because store is nil
		// We wrap in recovery to verify it panics
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic with nil store")
			}
		}()

		mux.ServeHTTP(w, req)
	})

	t.Run("create session with nil store panics", func(t *testing.T) {
		body := `{"title": "Test"}`
		req := httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic with nil store")
			}
		}()

		mux.ServeHTTP(w, req)
	})
}

// TestSessionHandler_InvalidRequest tests invalid request handling
func TestSessionHandler_InvalidRequest(t *testing.T) {
	// Create a server without store to test request parsing
	// The handler should return 400 for invalid JSON before accessing store
	handler := NewSessionHandler(nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	t.Run("create session with invalid JSON", func(t *testing.T) {
		body := `{invalid json}`
		req := httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid request body")
	})
}
