package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/koopa0/koopa-cli/internal/log"
	"github.com/stretchr/testify/assert"
)

func TestRecoveryMiddleware_NoPanic(t *testing.T) {
	logger := log.NewNop()
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	wrapped := recoveryMiddleware(logger)(handler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "success", w.Body.String())
}

func TestRecoveryMiddleware_WithPanic(t *testing.T) {
	logger := log.NewNop()
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("test panic")
	})

	wrapped := recoveryMiddleware(logger)(handler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	// Should not panic
	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "internal server error")
}

func TestLoggingMiddleware(t *testing.T) {
	logger := log.NewNop()
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := loggingMiddleware(logger)(handler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLoggingMiddleware_CapturesStatusCode(t *testing.T) {
	var buf bytes.Buffer
	// Use debug level (-4 = slog.LevelDebug) to ensure log is written
	logger := log.NewWithWriter(&buf, log.Config{Level: -4})

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	wrapped := loggingMiddleware(logger)(handler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	// Verify that status code is logged (slog text format uses status=404)
	assert.Contains(t, buf.String(), "status=404")
}

func TestStatusRecorder(t *testing.T) {
	t.Run("captures status code", func(t *testing.T) {
		w := httptest.NewRecorder()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		rec.WriteHeader(http.StatusCreated)

		assert.Equal(t, http.StatusCreated, rec.status)
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("default status is 200", func(t *testing.T) {
		w := httptest.NewRecorder()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		// Write body without explicit WriteHeader
		_, _ = rec.Write([]byte("test"))

		assert.Equal(t, http.StatusOK, rec.status)
	})
}

func TestChain(t *testing.T) {
	var order []string

	middleware1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m1-before")
			next.ServeHTTP(w, r)
			order = append(order, "m1-after")
		})
	}

	middleware2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m2-before")
			next.ServeHTTP(w, r)
			order = append(order, "m2-after")
		})
	}

	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		order = append(order, "handler")
	})

	wrapped := chain(handler, middleware1, middleware2)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// middleware1 wraps middleware2 wraps handler
	// so execution order is: m1-before -> m2-before -> handler -> m2-after -> m1-after
	assert.Equal(t, []string{"m1-before", "m2-before", "handler", "m2-after", "m1-after"}, order)
}
