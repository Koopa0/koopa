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

// Note: Full Session handler testing requires integration tests with testcontainer.
// These unit tests cover request parsing and error handling.

func TestSession_List_Integration(t *testing.T) {
	t.Skip("requires integration test with testcontainer")
}

func TestSession_Create_Integration(t *testing.T) {
	t.Skip("requires integration test with testcontainer")
}

// TestSession_RequestParsing tests request body parsing.
func TestSession_RequestParsing(t *testing.T) {
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

// TestSession_NilStore tests behavior when store is nil.
// Nil store returns 500 instead of panicking (defensive programming).
func TestSession_NilStore(t *testing.T) {
	logger := log.NewNop()
	handler := NewSession(nil, logger)
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

// TestSession_InvalidRequest tests invalid request handling.
// With nil store, requests return 500 before reaching JSON parsing (fail-fast).
func TestSession_InvalidRequest(t *testing.T) {
	logger := log.NewNop()
	handler := NewSession(nil, logger)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	t.Run("create session with nil store returns 500 before JSON parsing", func(t *testing.T) {
		body := `{invalid json}`
		req := httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestSession_InputValidation tests input validation.
func TestSession_InputValidation(t *testing.T) {
	t.Skip("requires integration test with testcontainer")
}

// TestSession_Pagination tests pagination parameter parsing.
func TestSession_Pagination(t *testing.T) {
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
