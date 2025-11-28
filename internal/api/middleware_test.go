package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/koopa0/koopa-cli/internal/log"
	"github.com/stretchr/testify/assert"
)

func TestRecoveryMiddleware_PanicRecovery(t *testing.T) {
	logger := log.NewNop()

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	handler := RecoveryMiddleware(logger)(panicHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()

	// Should not panic
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestLoggingMiddleware_CapturesMetrics(t *testing.T) {
	logger := log.NewNop()

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("test response"))
	})

	handler := LoggingMiddleware(logger)(innerHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "test response", w.Body.String())
}

func TestLoggingWriter_DefaultStatus(t *testing.T) {
	w := httptest.NewRecorder()
	lw := &loggingWriter{ResponseWriter: w, statusCode: http.StatusOK}

	// Write without calling WriteHeader should default to 200
	_, err := lw.Write([]byte("hello"))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, lw.statusCode)
}

func TestLoggingWriter_Unwrap(t *testing.T) {
	w := httptest.NewRecorder()
	lw := &loggingWriter{ResponseWriter: w}

	// Unwrap should return the underlying ResponseWriter
	assert.Equal(t, w, lw.Unwrap())
}

func TestAuthMiddleware_ExemptPaths(t *testing.T) {
	logger := log.NewNop()

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Set API key to enable auth
	t.Setenv(APIKeyEnvVar, "test-api-key")
	handler := AuthMiddleware(logger)(innerHandler)

	exemptPaths := []string{"/health", "/ready", "/health/live", "/health/ready"}
	for _, path := range exemptPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			// Should pass without auth
			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

func TestAuthMiddleware_DevMode(t *testing.T) {
	logger := log.NewNop()

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// No API key = dev mode
	t.Setenv(APIKeyEnvVar, "")
	handler := AuthMiddleware(logger)(innerHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/test", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should pass without auth in dev mode
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestExtractAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name:     "X-API-Key header",
			headers:  map[string]string{APIKeyHeader: "my-api-key"},
			expected: "my-api-key",
		},
		{
			name:     "Bearer token",
			headers:  map[string]string{"Authorization": "Bearer my-bearer-token"},
			expected: "my-bearer-token",
		},
		{
			name:     "X-API-Key takes precedence",
			headers:  map[string]string{APIKeyHeader: "key1", "Authorization": "Bearer key2"},
			expected: "key1",
		},
		{
			name:     "no auth headers",
			headers:  map[string]string{},
			expected: "",
		},
		{
			name:     "invalid Authorization header",
			headers:  map[string]string{"Authorization": "Basic abc123"},
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			result := extractAPIKey(req)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsExemptPath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/health", true},
		{"/ready", true},
		{"/health/live", true},
		{"/health/ready", true},
		{"/api/chat", false},
		{"/api/sessions", false},
		{"/", false},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			result := isExemptPath(tc.path)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestChain(t *testing.T) {
	var order []string

	m1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m1-before")
			next.ServeHTTP(w, r)
			order = append(order, "m1-after")
		})
	}

	m2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m2-before")
			next.ServeHTTP(w, r)
			order = append(order, "m2-after")
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	})

	chained := Chain(handler, m1, m2)

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()

	chained.ServeHTTP(w, req)

	// m1 is first in the list, so it wraps outermost
	expected := []string{"m1-before", "m2-before", "handler", "m2-after", "m1-after"}
	assert.Equal(t, expected, order)
}
