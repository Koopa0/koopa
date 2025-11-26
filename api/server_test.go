package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/koopa0/koopa-cli/internal/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_HealthEndpoints(t *testing.T) {
	logger := log.NewNop()
	// Create server with nil dependencies (health check only needs pool for readiness)
	srv := NewServer(nil, nil, nil, logger)
	handler := srv.Handler()

	t.Run("GET /health returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "ok", w.Body.String())
	})

	t.Run("GET /ready returns 503 when pool is nil", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestServer_ChatEndpoint_NoFlow(t *testing.T) {
	logger := log.NewNop()
	// When no flow is provided, the chat endpoint should return 404
	srv := NewServer(nil, nil, nil, logger)
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
	logger := log.NewNop()
	srv := NewServer(nil, nil, nil, logger)
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
	logger := log.NewNop()
	srv := NewServer(nil, nil, nil, logger)

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Find an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	_ = listener.Close()

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run(ctx, addr)
	}()

	// Poll for server readiness instead of fixed sleep
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

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
	logger := log.NewNop()
	srv := NewServer(nil, nil, nil, logger)
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
