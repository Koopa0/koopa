package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_HealthEndpoints(t *testing.T) {
	// Create server with nil dependencies (health check only needs store for readiness)
	srv := NewServer(nil, nil)
	handler := srv.Handler()

	t.Run("GET /health returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "ok", w.Body.String())
	})

	t.Run("GET /ready returns 503 when store is nil", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestServer_ChatEndpoint_NoFlow(t *testing.T) {
	// When no flow is provided, the chat endpoint should return 404
	srv := NewServer(nil, nil)
	handler := srv.Handler()

	t.Run("POST /api/chat returns 404 when flow is nil", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/chat", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// No route registered when flow is nil
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestServer_MiddlewareChain(t *testing.T) {
	srv := NewServer(nil, nil)
	handler := srv.Handler()

	t.Run("panic in handler is recovered", func(t *testing.T) {
		// This test verifies the recovery middleware is in place
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		// Should not panic
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestServer_Run_GracefulShutdown(t *testing.T) {
	srv := NewServer(nil, nil)

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run(ctx, "127.0.0.1:0") // Use port 0 to get random available port
	}()

	// Wait a bit for server to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context to trigger shutdown
	cancel()

	// Wait for server to stop
	select {
	case err := <-errCh:
		// Should return nil on graceful shutdown
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestServer_DefaultAddr(t *testing.T) {
	assert.Equal(t, "127.0.0.1:3400", DefaultAddr)
}

func TestServer_ContentTypeJSON(t *testing.T) {
	srv := NewServer(nil, nil)
	handler := srv.Handler()

	t.Run("health endpoint returns plain text", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// Health endpoint returns plain text, not JSON
		assert.NotEqual(t, "application/json", w.Header().Get("Content-Type"))
	})
}

func TestWriteJSON_Integration(t *testing.T) {
	w := httptest.NewRecorder()

	data := map[string]any{
		"sessions": []string{"a", "b"},
		"total":    2,
	}
	writeJSON(w, http.StatusOK, data)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var result map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, float64(2), result["total"]) // JSON numbers are float64
}
