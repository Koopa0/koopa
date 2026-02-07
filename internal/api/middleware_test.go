package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestRecoveryMiddleware_Panic(t *testing.T) {
	logger := discardLogger()

	panicHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("test panic")
	})

	handler := recoveryMiddleware(logger)(panicHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("recoveryMiddleware(panic) status = %d, want %d", w.Code, http.StatusInternalServerError)
	}

	body := decodeErrorEnvelope(t, w)

	if body.Code != "internal_error" {
		t.Errorf("recoveryMiddleware(panic) code = %q, want %q", body.Code, "internal_error")
	}
}

func TestRecoveryMiddleware_NoPanic(t *testing.T) {
	logger := discardLogger()

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})

	handler := recoveryMiddleware(logger)(okHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("recoveryMiddleware(ok) status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestCORSMiddleware_AllowedOriginPreflight(t *testing.T) {
	origins := []string{"http://localhost:4200"}
	handler := corsMiddleware(origins)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("next handler should not be called for OPTIONS")
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodOptions, "/api/v1/chat", nil)
	r.Header.Set("Origin", "http://localhost:4200")

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("CORS preflight status = %d, want %d", w.Code, http.StatusNoContent)
	}

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:4200" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "http://localhost:4200")
	}

	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want %q", got, "true")
	}

	if got := w.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Error("Access-Control-Allow-Headers should be set")
	}
}

func TestCORSMiddleware_DisallowedOriginPreflight(t *testing.T) {
	origins := []string{"http://localhost:4200"}
	handler := corsMiddleware(origins)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("next handler should not be called for OPTIONS")
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodOptions, "/api/v1/chat", nil)
	r.Header.Set("Origin", "http://evil.com")

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("CORS disallowed preflight status = %d, want %d", w.Code, http.StatusNoContent)
	}

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty for disallowed origin", got)
	}
}

func TestCORSMiddleware_NormalRequest(t *testing.T) {
	origins := []string{"http://localhost:4200"}
	called := false
	handler := corsMiddleware(origins)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	r.Header.Set("Origin", "http://localhost:4200")

	handler.ServeHTTP(w, r)

	if !called {
		t.Error("next handler was not called")
	}

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:4200" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "http://localhost:4200")
	}
}

func TestCSRFMiddleware_SkipsGET(t *testing.T) {
	logger := discardLogger()
	sm := &sessionManager{
		hmacSecret: []byte("test-secret-at-least-32-characters!!"),
		logger:     logger,
	}

	called := false
	handler := csrfMiddleware(sm, logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)

	handler.ServeHTTP(w, r)

	if !called {
		t.Error("GET request should bypass CSRF check")
	}
}

func TestCSRFMiddleware_RejectsMissingToken(t *testing.T) {
	logger := discardLogger()
	sm := &sessionManager{
		hmacSecret: []byte("test-secret-at-least-32-characters!!"),
		logger:     logger,
	}

	handler := csrfMiddleware(sm, logger)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called without CSRF token")
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	// No X-CSRF-Token header, no session in context

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("CSRF missing token status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCSRFMiddleware_AcceptsValidPreSessionToken(t *testing.T) {
	logger := discardLogger()
	sm := &sessionManager{
		hmacSecret: []byte("test-secret-at-least-32-characters!!"),
		logger:     logger,
	}

	token := sm.NewPreSessionCSRFToken()

	called := false
	handler := csrfMiddleware(sm, logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	r.Header.Set("X-CSRF-Token", token)

	handler.ServeHTTP(w, r)

	if !called {
		t.Error("handler should be called with valid pre-session CSRF token")
	}
}

func TestCSRFMiddleware_AcceptsValidSessionToken(t *testing.T) {
	logger := discardLogger()
	sm := &sessionManager{
		hmacSecret: []byte("test-secret-at-least-32-characters!!"),
		logger:     logger,
	}

	sessionID := uuid.New()
	token := sm.NewCSRFToken(sessionID)

	called := false
	handler := csrfMiddleware(sm, logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	r.Header.Set("X-CSRF-Token", token)

	// Inject session ID into context (normally done by sessionMiddleware)
	ctx := context.WithValue(r.Context(), ctxKeySessionID, sessionID)
	r = r.WithContext(ctx)

	handler.ServeHTTP(w, r)

	if !called {
		t.Error("handler should be called with valid session-bound CSRF token")
	}
}

func TestCSRFMiddleware_RejectsInvalidToken(t *testing.T) {
	logger := discardLogger()
	sm := &sessionManager{
		hmacSecret: []byte("test-secret-at-least-32-characters!!"),
		logger:     logger,
	}

	sessionID := uuid.New()

	handler := csrfMiddleware(sm, logger)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called with invalid token")
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	r.Header.Set("X-CSRF-Token", "obviously-invalid-token")

	ctx := context.WithValue(r.Context(), ctxKeySessionID, sessionID)
	r = r.WithContext(ctx)

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("CSRF invalid token status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestSecurityHeaders(t *testing.T) {
	t.Run("production", func(t *testing.T) {
		w := httptest.NewRecorder()
		setSecurityHeaders(w, false)

		expected := map[string]string{
			"X-Content-Type-Options":    "nosniff",
			"X-Frame-Options":           "DENY",
			"Referrer-Policy":           "strict-origin-when-cross-origin",
			"Content-Security-Policy":   "default-src 'none'",
			"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		}

		for header, want := range expected {
			if got := w.Header().Get(header); got != want {
				t.Errorf("setSecurityHeaders(isDev=false) %q = %q, want %q", header, got, want)
			}
		}
	})

	t.Run("dev", func(t *testing.T) {
		w := httptest.NewRecorder()
		setSecurityHeaders(w, true)

		if got := w.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("setSecurityHeaders(isDev=true) HSTS = %q, want empty", got)
		}

		// Other headers should still be set
		if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("setSecurityHeaders(isDev=true) X-Content-Type-Options = %q, want %q", got, "nosniff")
		}
	})
}

// ============================================================================
// Rate Limiting Tests
// ============================================================================

func TestRateLimiter_AllowsWithinBurst(t *testing.T) {
	rl := newRateLimiter(1.0, 5)

	for i := range 5 {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("allow() returned false on request %d (within burst of 5)", i+1)
		}
	}
}

func TestRateLimiter_BlocksAfterBurst(t *testing.T) {
	rl := newRateLimiter(1.0, 3)

	// Exhaust the burst
	for range 3 {
		rl.allow("1.2.3.4")
	}

	if rl.allow("1.2.3.4") {
		t.Error("allow() should return false after burst exhausted")
	}
}

func TestRateLimiter_SeparateIPs(t *testing.T) {
	rl := newRateLimiter(1.0, 2)

	// Exhaust IP 1
	rl.allow("1.1.1.1")
	rl.allow("1.1.1.1")

	// IP 2 should still be allowed
	if !rl.allow("2.2.2.2") {
		t.Error("allow() should allow a different IP")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	rl := newRateLimiter(100.0, 1) // 100 tokens/sec so we can test quickly

	// Use the single token
	rl.allow("1.2.3.4")

	if rl.allow("1.2.3.4") {
		t.Error("allow() should be blocked immediately after burst exhausted")
	}

	// Wait enough time for a token to refill
	time.Sleep(20 * time.Millisecond)

	if !rl.allow("1.2.3.4") {
		t.Error("allow() should be allowed after token refill")
	}
}

func TestRateLimitMiddleware_Returns429(t *testing.T) {
	rl := newRateLimiter(0.001, 1) // Very low rate
	logger := discardLogger()

	handler := rateLimitMiddleware(rl, false, logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request should succeed
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want %d", w.Code, http.StatusOK)
	}

	// Second request should be rate limited
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited request status = %d, want %d", w.Code, http.StatusTooManyRequests)
	}

	if got := w.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want %q", got, "1")
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		trustProxy bool
		remoteAddr string
		xff        string
		xri        string
		want       string
	}{
		{
			name:       "remote addr with port",
			trustProxy: true,
			remoteAddr: "10.0.0.1:12345",
			want:       "10.0.0.1",
		},
		{
			name:       "X-Forwarded-For single when trusted",
			trustProxy: true,
			remoteAddr: "127.0.0.1:80",
			xff:        "203.0.113.50",
			want:       "203.0.113.50",
		},
		{
			name:       "X-Forwarded-For multiple when trusted",
			trustProxy: true,
			remoteAddr: "127.0.0.1:80",
			xff:        "203.0.113.50, 70.41.3.18, 150.172.238.178",
			want:       "203.0.113.50",
		},
		{
			name:       "X-Real-IP when trusted",
			trustProxy: true,
			remoteAddr: "127.0.0.1:80",
			xri:        "203.0.113.50",
			want:       "203.0.113.50",
		},
		{
			name:       "X-Real-IP takes precedence over X-Forwarded-For when trusted",
			trustProxy: true,
			remoteAddr: "127.0.0.1:80",
			xff:        "203.0.113.50",
			xri:        "198.51.100.1",
			want:       "198.51.100.1",
		},
		{
			name:       "untrusted ignores X-Forwarded-For",
			trustProxy: false,
			remoteAddr: "10.0.0.1:12345",
			xff:        "203.0.113.50",
			want:       "10.0.0.1",
		},
		{
			name:       "untrusted ignores X-Real-IP",
			trustProxy: false,
			remoteAddr: "10.0.0.1:12345",
			xri:        "203.0.113.50",
			want:       "10.0.0.1",
		},
		{
			name:       "invalid X-Real-IP falls through to XFF",
			trustProxy: true,
			remoteAddr: "127.0.0.1:80",
			xri:        "not-an-ip",
			xff:        "203.0.113.50",
			want:       "203.0.113.50",
		},
		{
			name:       "invalid XFF falls through to RemoteAddr",
			trustProxy: true,
			remoteAddr: "127.0.0.1:80",
			xff:        "not-an-ip",
			want:       "127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				r.Header.Set("X-Real-IP", tt.xri)
			}

			if got := clientIP(r, tt.trustProxy); got != tt.want {
				t.Errorf("clientIP(r, %v) = %q, want %q", tt.trustProxy, got, tt.want)
			}
		})
	}
}

func TestSessionIDFromContext(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		id := uuid.New()
		ctx := context.WithValue(context.Background(), ctxKeySessionID, id)

		got, ok := SessionIDFromContext(ctx)
		if !ok {
			t.Fatal("expected session ID to be present")
		}
		if got != id {
			t.Errorf("SessionIDFromContext() = %s, want %s", got, id)
		}
	})

	t.Run("absent", func(t *testing.T) {
		_, ok := SessionIDFromContext(context.Background())
		if ok {
			t.Error("expected session ID to be absent")
		}
	})
}
