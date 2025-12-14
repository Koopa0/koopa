package web

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/web/handlers"
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

// TestGetSessionID verifies session ID retrieval from context.
func TestGetSessionID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setupCtx  func() context.Context
		wantOK    bool
		wantIsNil bool
	}{
		{
			name: "session ID exists in context",
			setupCtx: func() context.Context {
				sessionID := uuid.New()
				return context.WithValue(context.Background(), ctxKeySessionID, sessionID)
			},
			wantOK:    true,
			wantIsNil: false,
		},
		{
			name: "session ID not in context",
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantOK:    false,
			wantIsNil: true,
		},
		{
			name: "wrong type in context",
			setupCtx: func() context.Context {
				return context.WithValue(context.Background(), ctxKeySessionID, "not-a-uuid")
			},
			wantOK:    false,
			wantIsNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := tt.setupCtx()
			sessionID, ok := GetSessionID(ctx)

			if ok != tt.wantOK {
				t.Errorf("GetSessionID() ok = %v, want %v", ok, tt.wantOK)
			}

			if tt.wantIsNil && sessionID != uuid.Nil {
				t.Errorf("GetSessionID() returned non-nil UUID when not expected")
			}

			if !tt.wantIsNil && sessionID == uuid.Nil && tt.wantOK {
				t.Errorf("GetSessionID() returned nil UUID when session should exist")
			}
		})
	}
}

// TestRequireSession is tested in integration tests (pages_history_test.go)
// because it requires a real database store to call GetOrCreate().
// Unit tests focus on GetSessionID and RequireCSRF which don't need database access.

// TestRequireCSRF verifies CSRF validation middleware.
func TestRequireCSRF(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	sessions := handlers.NewSessions(nil, []byte("test-secret-key-at-least-32-characters-long"), true)

	t.Run("success: valid CSRF token", func(t *testing.T) {
		t.Parallel()

		// Create session and CSRF token
		sessionID := uuid.New()
		csrfToken := sessions.NewCSRFToken(sessionID)

		// Handler that should be called
		called := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})

		middleware := RequireCSRF(sessions, logger)
		wrapped := middleware(handler)

		// Create request with session in context and valid CSRF token
		form := url.Values{}
		form.Set("csrf_token", csrfToken)
		form.Set("content", "test message")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx := context.WithValue(req.Context(), ctxKeySessionID, sessionID)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		// Verify
		if rec.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
		}

		if !called {
			t.Error("Handler was not called despite valid CSRF token")
		}
	})

	t.Run("skip validation for GET request", func(t *testing.T) {
		t.Parallel()

		called := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})

		middleware := RequireCSRF(sessions, logger)
		wrapped := middleware(handler)

		// GET request without CSRF token should pass
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
		}

		if !called {
			t.Error("Handler was not called for safe GET request")
		}
	})

	t.Run("skip validation for HEAD request", func(t *testing.T) {
		t.Parallel()

		called := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})

		middleware := RequireCSRF(sessions, logger)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodHead, "/test", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
		}

		if !called {
			t.Error("Handler was not called for safe HEAD request")
		}
	})

	t.Run("fail: session ID not in context", func(t *testing.T) {
		t.Parallel()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Handler should not be called when session ID missing")
		})

		middleware := RequireCSRF(sessions, logger)
		wrapped := middleware(handler)

		form := url.Values{}
		form.Set("csrf_token", "any-token")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// No session ID in context

		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusForbidden)
		}

		body := strings.TrimSpace(rec.Body.String())
		if !strings.Contains(body, "session required") {
			t.Errorf("Body = %q, want session error", body)
		}
	})

	t.Run("fail: invalid CSRF token", func(t *testing.T) {
		t.Parallel()

		sessionID := uuid.New()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Handler should not be called with invalid CSRF token")
		})

		middleware := RequireCSRF(sessions, logger)
		wrapped := middleware(handler)

		form := url.Values{}
		form.Set("csrf_token", "invalid-token-12345")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx := context.WithValue(req.Context(), ctxKeySessionID, sessionID)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusForbidden)
		}

		body := strings.TrimSpace(rec.Body.String())
		if !strings.Contains(body, "CSRF validation failed") {
			t.Errorf("Body = %q, want CSRF error", body)
		}
	})

	t.Run("fail: missing CSRF token", func(t *testing.T) {
		t.Parallel()

		sessionID := uuid.New()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Handler should not be called without CSRF token")
		})

		middleware := RequireCSRF(sessions, logger)
		wrapped := middleware(handler)

		// Form without CSRF token
		form := url.Values{}
		form.Set("content", "test message")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx := context.WithValue(req.Context(), ctxKeySessionID, sessionID)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusForbidden)
		}

		body := strings.TrimSpace(rec.Body.String())
		if !strings.Contains(body, "CSRF validation failed") {
			t.Errorf("Body = %q, want CSRF error", body)
		}
	})
}

// flushableRecorder is a custom ResponseRecorder that implements http.Flusher.
type flushableRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (f *flushableRecorder) Flush() {
	f.flushed = true
}

// TestMethodOverride verifies the _method form field override middleware.
func TestMethodOverride(t *testing.T) {
	t.Parallel()

	// Helper to create handler that records the method it sees
	makeHandler := func(gotMethod *string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*gotMethod = r.Method
			w.WriteHeader(http.StatusOK)
		})
	}

	t.Run("POST with _method=DELETE converts to DELETE", func(t *testing.T) {
		t.Parallel()

		var gotMethod string
		handler := MethodOverride(makeHandler(&gotMethod))

		form := url.Values{}
		form.Set("_method", "DELETE")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if gotMethod != http.MethodDelete {
			t.Errorf("Method = %q, want %q", gotMethod, http.MethodDelete)
		}
	})

	t.Run("POST with _method=PUT converts to PUT", func(t *testing.T) {
		t.Parallel()

		var gotMethod string
		handler := MethodOverride(makeHandler(&gotMethod))

		form := url.Values{}
		form.Set("_method", "PUT")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if gotMethod != http.MethodPut {
			t.Errorf("Method = %q, want %q", gotMethod, http.MethodPut)
		}
	})

	t.Run("POST with _method=PATCH converts to PATCH", func(t *testing.T) {
		t.Parallel()

		var gotMethod string
		handler := MethodOverride(makeHandler(&gotMethod))

		form := url.Values{}
		form.Set("_method", "PATCH")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if gotMethod != http.MethodPatch {
			t.Errorf("Method = %q, want %q", gotMethod, http.MethodPatch)
		}
	})

	t.Run("POST with _method=GET stays POST (security)", func(t *testing.T) {
		t.Parallel()

		var gotMethod string
		handler := MethodOverride(makeHandler(&gotMethod))

		form := url.Values{}
		form.Set("_method", "GET")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if gotMethod != http.MethodPost {
			t.Errorf("Method = %q, want %q (should not allow GET override)", gotMethod, http.MethodPost)
		}
	})

	t.Run("POST without _method stays POST", func(t *testing.T) {
		t.Parallel()

		var gotMethod string
		handler := MethodOverride(makeHandler(&gotMethod))

		form := url.Values{}
		form.Set("content", "test")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if gotMethod != http.MethodPost {
			t.Errorf("Method = %q, want %q", gotMethod, http.MethodPost)
		}
	})

	t.Run("GET with _method=DELETE stays GET (only POST is overridden)", func(t *testing.T) {
		t.Parallel()

		var gotMethod string
		handler := MethodOverride(makeHandler(&gotMethod))

		req := httptest.NewRequest(http.MethodGet, "/test?_method=DELETE", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if gotMethod != http.MethodGet {
			t.Errorf("Method = %q, want %q (only POST should be overridable)", gotMethod, http.MethodGet)
		}
	})

	t.Run("XSS injection in _method is ignored", func(t *testing.T) {
		t.Parallel()

		var gotMethod string
		handler := MethodOverride(makeHandler(&gotMethod))

		form := url.Values{}
		form.Set("_method", "<script>alert('xss')</script>")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if gotMethod != http.MethodPost {
			t.Errorf("Method = %q, want %q (XSS payload should be ignored)", gotMethod, http.MethodPost)
		}
	})

	t.Run("empty _method stays POST", func(t *testing.T) {
		t.Parallel()

		var gotMethod string
		handler := MethodOverride(makeHandler(&gotMethod))

		form := url.Values{}
		form.Set("_method", "")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if gotMethod != http.MethodPost {
			t.Errorf("Method = %q, want %q", gotMethod, http.MethodPost)
		}
	})

	t.Run("lowercase _method=delete stays POST (case sensitive)", func(t *testing.T) {
		t.Parallel()

		var gotMethod string
		handler := MethodOverride(makeHandler(&gotMethod))

		form := url.Values{}
		form.Set("_method", "delete")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if gotMethod != http.MethodPost {
			t.Errorf("Method = %q, want %q (lowercase should be ignored)", gotMethod, http.MethodPost)
		}
	})
}
