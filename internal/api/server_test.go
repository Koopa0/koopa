package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/koopa0/koopa/internal/session"
)

// testStore creates a session.Store with nil database connections.
// It is valid for Server construction but will panic on any DB call.
// The recovery middleware handles such panics in route registration tests.
func testStore() *session.Store {
	return session.New(nil, nil, slog.New(slog.DiscardHandler))
}

func testCSRFSecret() []byte {
	return []byte("test-secret-at-least-32-characters!!")
}

func TestNewServer(t *testing.T) {
	srv, err := NewServer(context.Background(), ServerConfig{
		Logger:       slog.New(slog.DiscardHandler),
		SessionStore: testStore(),
		CSRFSecret:   testCSRFSecret(),
		CORSOrigins:  []string{"http://localhost:4200"},
		IsDev:        true,
	})

	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	if srv == nil {
		t.Fatal("NewServer() returned nil")
	}

	if srv.Handler() == nil {
		t.Fatal("NewServer().Handler() returned nil")
	}
}

func TestNewServer_MissingStore(t *testing.T) {
	_, err := NewServer(context.Background(), ServerConfig{
		CSRFSecret: testCSRFSecret(),
	})

	if err == nil {
		t.Fatal("NewServer(nil store) expected error, got nil")
	}
}

func TestNewServer_ShortCSRFSecret(t *testing.T) {
	_, err := NewServer(context.Background(), ServerConfig{
		SessionStore: testStore(),
		CSRFSecret:   []byte("too-short"),
	})

	if err == nil {
		t.Fatal("NewServer(short secret) expected error, got nil")
	}
}

func TestHealthEndpoint(t *testing.T) {
	srv, err := NewServer(context.Background(), ServerConfig{
		Logger:       slog.New(slog.DiscardHandler),
		SessionStore: testStore(),
		CSRFSecret:   testCSRFSecret(),
		IsDev:        true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health", nil)

	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /health status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestReadyEndpoint(t *testing.T) {
	srv, err := NewServer(context.Background(), ServerConfig{
		Logger:       slog.New(slog.DiscardHandler),
		SessionStore: testStore(),
		CSRFSecret:   testCSRFSecret(),
		IsDev:        true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ready", nil)

	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /ready status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequestIDMiddleware_GeneratesID(t *testing.T) {
	handler := requestIDMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(w, r)

	got := w.Header().Get("X-Request-ID")
	if got == "" {
		t.Fatal("requestIDMiddleware() did not set X-Request-ID header")
	}
	if _, err := uuid.Parse(got); err != nil {
		t.Errorf("requestIDMiddleware() X-Request-ID = %q, not a valid UUID", got)
	}
}

func TestRequestIDMiddleware_ReusesValid(t *testing.T) {
	want := uuid.New().String()

	handler := requestIDMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Request-ID", want)

	handler.ServeHTTP(w, r)

	got := w.Header().Get("X-Request-ID")
	if got != want {
		t.Errorf("requestIDMiddleware(valid) X-Request-ID = %q, want %q", got, want)
	}
}

func TestRequestIDMiddleware_RejectsInvalid(t *testing.T) {
	handler := requestIDMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Request-ID", "not-a-valid-uuid")

	handler.ServeHTTP(w, r)

	got := w.Header().Get("X-Request-ID")
	if got == "not-a-valid-uuid" {
		t.Error("requestIDMiddleware(invalid) should not reuse invalid X-Request-ID")
	}
	if _, err := uuid.Parse(got); err != nil {
		t.Errorf("requestIDMiddleware(invalid) X-Request-ID = %q, not a valid UUID", got)
	}
}

func TestRequestIDMiddleware_InContext(t *testing.T) {
	want := uuid.New().String()

	var gotFromCtx string
	handler := requestIDMiddleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotFromCtx = requestIDFromContext(r.Context())
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Request-ID", want)

	handler.ServeHTTP(w, r)

	if gotFromCtx != want {
		t.Errorf("requestIDFromContext() = %q, want %q", gotFromCtx, want)
	}
}

func TestRouteRegistration(t *testing.T) {
	srv, err := NewServer(context.Background(), ServerConfig{
		Logger:       slog.New(slog.DiscardHandler),
		SessionStore: testStore(),
		CSRFSecret:   testCSRFSecret(),
		CORSOrigins:  []string{"http://localhost:4200"},
		IsDev:        true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	tests := []struct {
		method string
		path   string
		want   int // expected status code (not 404 means route exists)
	}{
		// Health probes (no middleware)
		{http.MethodGet, "/health", http.StatusOK},
		{http.MethodGet, "/ready", http.StatusOK},
		// Non-existent route
		{http.MethodGet, "/nonexistent", http.StatusNotFound},
		// API routes — exact status depends on middleware/handler,
		// but should NOT be 404 (route must exist)
		{http.MethodGet, "/api/v1/csrf-token", http.StatusOK},                      // Returns pre-session token
		{http.MethodGet, "/api/v1/sessions/" + uuid.New().String() + "/export", 0}, // Export (will fail ownership, not 404)
		// Search + Stats routes (requires user context, but route must exist)
		{http.MethodGet, "/api/v1/search?q=test", 0},
		{http.MethodGet, "/api/v1/stats", 0},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(tt.method, tt.path, nil)

			srv.Handler().ServeHTTP(w, r)

			if tt.want == http.StatusNotFound {
				if w.Code != http.StatusNotFound {
					t.Errorf("route %s %s status = %d, want %d", tt.method, tt.path, w.Code, http.StatusNotFound)
				}
			} else {
				if w.Code == http.StatusNotFound {
					t.Errorf("route %s %s should exist (got 404)", tt.method, tt.path)
				}
				if tt.want != 0 && w.Code != tt.want {
					t.Errorf("route %s %s status = %d, want %d", tt.method, tt.path, w.Code, tt.want)
				}
			}
		})
	}
}
