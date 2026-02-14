package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

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
		WriteJSON(w, http.StatusOK, map[string]string{"ok": "true"}, nil)
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

	userID := uuid.New().String()
	token := sm.NewCSRFToken(userID)

	called := false
	handler := csrfMiddleware(sm, logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	r.Header.Set("X-CSRF-Token", token)

	// Inject user ID into context (normally done by userMiddleware)
	ctx := context.WithValue(r.Context(), ctxKeyUserID, userID)
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

	userID := uuid.New().String()

	handler := csrfMiddleware(sm, logger)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called with invalid token")
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	r.Header.Set("X-CSRF-Token", "obviously-invalid-token")

	ctx := context.WithValue(r.Context(), ctxKeyUserID, userID)
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

		wantHeaders := map[string]string{
			"X-Content-Type-Options":    "nosniff",
			"X-Frame-Options":           "DENY",
			"Referrer-Policy":           "strict-origin-when-cross-origin",
			"Content-Security-Policy":   "default-src 'none'",
			"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		}

		for header, want := range wantHeaders {
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

func Test_sessionIDFromContext(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		id := uuid.New()
		ctx := context.WithValue(context.Background(), ctxKeySessionID, id)

		got, ok := sessionIDFromContext(ctx)
		if !ok {
			t.Fatal("sessionIDFromContext() ok = false, want true")
		}
		if got != id {
			t.Errorf("sessionIDFromContext() = %s, want %s", got, id)
		}
	})

	t.Run("absent", func(t *testing.T) {
		_, ok := sessionIDFromContext(context.Background())
		if ok {
			t.Error("sessionIDFromContext(empty) ok = true, want false")
		}
	})
}

func TestSessionMiddleware_GET_WithCookie(t *testing.T) {
	logger := discardLogger()
	sm := &sessionManager{
		hmacSecret: []byte("test-secret-at-least-32-characters!!"),
		logger:     logger,
	}

	sessionID := uuid.New()

	var gotID uuid.UUID
	var gotOK bool
	handler := sessionMiddleware(sm)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotID, gotOK = sessionIDFromContext(r.Context())
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	r.AddCookie(&http.Cookie{Name: "sid", Value: sessionID.String()})

	handler.ServeHTTP(w, r)

	if !gotOK {
		t.Fatal("sessionMiddleware(GET, valid cookie) expected session ID in context")
	}
	if gotID != sessionID {
		t.Errorf("sessionMiddleware(GET, valid cookie) session ID = %s, want %s", gotID, sessionID)
	}
}

func TestSessionMiddleware_GET_WithoutCookie(t *testing.T) {
	logger := discardLogger()
	sm := &sessionManager{
		hmacSecret: []byte("test-secret-at-least-32-characters!!"),
		logger:     logger,
	}

	var gotOK bool
	called := false
	handler := sessionMiddleware(sm)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		_, gotOK = sessionIDFromContext(r.Context())
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)

	handler.ServeHTTP(w, r)

	if !called {
		t.Fatal("sessionMiddleware(GET, no cookie) did not call next handler")
	}
	if gotOK {
		t.Error("sessionMiddleware(GET, no cookie) should not have session ID in context")
	}
}

func TestSessionMiddleware_GET_InvalidCookie(t *testing.T) {
	logger := discardLogger()
	sm := &sessionManager{
		hmacSecret: []byte("test-secret-at-least-32-characters!!"),
		logger:     logger,
	}

	var gotOK bool
	handler := sessionMiddleware(sm)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, gotOK = sessionIDFromContext(r.Context())
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	r.AddCookie(&http.Cookie{Name: "sid", Value: "not-a-uuid"})

	handler.ServeHTTP(w, r)

	if gotOK {
		t.Error("sessionMiddleware(GET, invalid cookie) should not have session ID in context")
	}
}

func TestLoggingMiddleware(t *testing.T) {
	logger := discardLogger()

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write([]byte("hello")); err != nil {
			t.Errorf("Write() error: %v", err)
		}
	})

	handler := loggingMiddleware(logger)(inner)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/test", nil)

	handler.ServeHTTP(w, r)

	if !called {
		t.Fatal("loggingMiddleware did not call next handler")
	}
	if w.Code != http.StatusCreated {
		t.Errorf("loggingMiddleware status = %d, want %d", w.Code, http.StatusCreated)
	}
	if w.Body.String() != "hello" {
		t.Errorf("loggingMiddleware body = %q, want %q", w.Body.String(), "hello")
	}
}
