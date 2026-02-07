package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

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
	srv, err := NewServer(ServerConfig{
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
	_, err := NewServer(ServerConfig{
		CSRFSecret: testCSRFSecret(),
	})

	if err == nil {
		t.Fatal("NewServer(nil store) expected error, got nil")
	}
}

func TestNewServer_ShortCSRFSecret(t *testing.T) {
	_, err := NewServer(ServerConfig{
		SessionStore: testStore(),
		CSRFSecret:   []byte("too-short"),
	})

	if err == nil {
		t.Fatal("NewServer(short secret) expected error, got nil")
	}
}

func TestHealthEndpoint(t *testing.T) {
	srv, err := NewServer(ServerConfig{
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
	srv, err := NewServer(ServerConfig{
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

func TestRouteRegistration(t *testing.T) {
	srv, err := NewServer(ServerConfig{
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
		{http.MethodGet, "/api/v1/csrf-token", http.StatusOK}, // Returns pre-session token
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
