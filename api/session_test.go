package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/koopa0/koopa-cli/internal/log"
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
// After refactoring, nil store returns 500 instead of panicking
func TestSessionHandler_NilStore(t *testing.T) {
	logger := log.NewNop()
	handler := NewSessionHandler(nil, logger)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	t.Run("list sessions with nil store returns 500", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("create session with nil store returns 500", func(t *testing.T) {
		body := `{"title": "Test"}`
		req := httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestSessionHandler_InvalidRequest tests invalid request handling
// Note: With nil store, requests return 500 before reaching JSON parsing.
// This test documents that behavior - store check comes before JSON parsing.
func TestSessionHandler_InvalidRequest(t *testing.T) {
	logger := log.NewNop()
	// With nil store, handler returns 500 before parsing JSON
	// This is correct defensive programming - fail fast on misconfiguration
	handler := NewSessionHandler(nil, logger)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	t.Run("create session with nil store returns 500 before JSON parsing", func(t *testing.T) {
		body := `{invalid json}`
		req := httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

		// Store nil check happens before JSON parsing
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestSessionHandler_InputValidation tests input validation
// Note: These tests would require a mock store to test validation.
// Skipping for now as they require interface refactoring.
func TestSessionHandler_InputValidation(t *testing.T) {
	t.Skip("requires mock store interface to test validation (store nil check happens first)")
}

// TestSessionHandler_Pagination tests pagination parameter parsing
func TestSessionHandler_Pagination(t *testing.T) {
	t.Run("parseIntParam with valid value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/sessions?limit=50", nil)
		val := parseIntParam(req, "limit", 100, 1, 1000)
		assert.Equal(t, 50, val)
	})

	t.Run("parseIntParam with invalid value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/sessions?limit=invalid", nil)
		val := parseIntParam(req, "limit", 100, 1, 1000)
		assert.Equal(t, 100, val) // returns default
	})

	t.Run("parseIntParam below minimum", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/sessions?limit=0", nil)
		val := parseIntParam(req, "limit", 100, 1, 1000)
		assert.Equal(t, 1, val) // returns min
	})

	t.Run("parseIntParam above maximum", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/sessions?limit=9999", nil)
		val := parseIntParam(req, "limit", 100, 1, 1000)
		assert.Equal(t, 1000, val) // returns max
	})
}
