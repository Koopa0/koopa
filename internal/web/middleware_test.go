package web

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLoggingMiddleware_CapturesMetrics verifies that the middleware logs request metrics.
func TestLoggingMiddleware_CapturesMetrics(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("test response"))
	})

	middleware := LoggingMiddleware(logger)(handler)

	req := httptest.NewRequest(http.MethodPost, "/test/path", http.NoBody)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	// Verify response
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}
	if w.Body.String() != "test response" {
		t.Errorf("body = %q, want %q", w.Body.String(), "test response")
	}

	// Verify logging output contains expected fields
	logOutput := logBuf.String()
	expectedFields := []string{
		"http request",
		"method=POST",
		"path=/test/path",
		"status=201",
		"bytes=13",
		"duration=",
		"ip=192.168.1.1:12345",
	}

	for _, field := range expectedFields {
		if !strings.Contains(logOutput, field) {
			t.Errorf("log output missing field %q, got: %s", field, logOutput)
		}
	}
}

// TestLoggingMiddleware_DefaultsStatusTo200 verifies implicit 200 status.
func TestLoggingMiddleware_DefaultsStatusTo200(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Write without calling WriteHeader - should default to 200
		_, _ = w.Write([]byte("ok"))
	})

	middleware := LoggingMiddleware(logger)(handler)

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "status=200") {
		t.Errorf("log missing status=200, got: %s", logOutput)
	}
}

// TestLoggingMiddleware_PreservesFlusher verifies Flush() passthrough for SSE.
func TestLoggingMiddleware_PreservesFlusher(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))

	flushed := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter does not implement http.Flusher")
		}
		// Mock flush by setting flag (real Flush is tested in integration)
		f.Flush()
		flushed = true
	})

	middleware := LoggingMiddleware(logger)(handler)

	// Use custom ResponseWriter that implements Flusher
	req := httptest.NewRequest(http.MethodGet, "/stream", http.NoBody)
	w := &flushableRecorder{ResponseRecorder: httptest.NewRecorder()}

	middleware.ServeHTTP(w, req)

	if !flushed {
		t.Error("Flush() was not called")
	}
	if !w.flushed {
		t.Error("underlying Flush() was not called")
	}
}

// TestLoggingMiddleware_Unwrap verifies Unwrap() for ResponseController.
func TestLoggingMiddleware_Unwrap(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))

	var underlying http.ResponseWriter
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// ResponseController requires Unwrap()
		type unwrapper interface {
			Unwrap() http.ResponseWriter
		}
		u, ok := w.(unwrapper)
		if !ok {
			t.Fatal("ResponseWriter does not implement Unwrap()")
		}
		underlying = u.Unwrap()
	})

	middleware := LoggingMiddleware(logger)(handler)

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	if underlying != w {
		t.Error("Unwrap() did not return underlying ResponseWriter")
	}
}

// TestRecoveryMiddleware_PanicRecovery verifies panic recovery before headers sent.
func TestRecoveryMiddleware_PanicRecovery(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError}))

	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("test panic")
	})

	middleware := RecoveryMiddleware(logger)(handler)

	req := httptest.NewRequest(http.MethodGet, "/panic-test", http.NoBody)
	w := httptest.NewRecorder()

	// Should not panic
	middleware.ServeHTTP(w, req)

	// Should return 500 error
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}

	// Should log the panic
	logOutput := logBuf.String()
	expectedFields := []string{
		"panic recovered",
		"error=\"test panic\"",
		"path=/panic-test",
		"headers_sent=false",
	}

	for _, field := range expectedFields {
		if !strings.Contains(logOutput, field) {
			t.Errorf("log output missing field %q, got: %s", field, logOutput)
		}
	}
}

// TestRecoveryMiddleware_PanicAfterHeadersSent verifies handling when headers already sent.
func TestRecoveryMiddleware_PanicAfterHeadersSent(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial response"))
		panic("late panic")
	})

	middleware := RecoveryMiddleware(logger)(handler)

	req := httptest.NewRequest(http.MethodGet, "/late-panic", http.NoBody)
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	// Status should be 200 (headers were sent before panic)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	// Should have partial response
	if !strings.Contains(w.Body.String(), "partial response") {
		t.Errorf("body missing partial response: %s", w.Body.String())
	}

	// Should log both panic and warning about headers already sent
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "panic recovered") {
		t.Error("log missing panic recovered message")
	}
	if !strings.Contains(logOutput, "cannot send error response") {
		t.Error("log missing 'cannot send error response' warning")
	}
	if !strings.Contains(logOutput, "headers_sent=true") {
		t.Error("log missing headers_sent=true")
	}
}

// TestRecoveryMiddleware_NoPanic verifies normal operation without panics.
func TestRecoveryMiddleware_NoPanic(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError}))

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	middleware := RecoveryMiddleware(logger)(handler)

	req := httptest.NewRequest(http.MethodGet, "/normal", http.NoBody)
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if w.Body.String() != "success" {
		t.Errorf("body = %q, want %q", w.Body.String(), "success")
	}

	// Should not log anything on success
	if logBuf.Len() > 0 {
		t.Errorf("unexpected log output: %s", logBuf.String())
	}
}

// flushableRecorder is a custom ResponseRecorder that implements http.Flusher.
type flushableRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (f *flushableRecorder) Flush() {
	f.flushed = true
}
