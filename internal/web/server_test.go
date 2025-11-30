package web_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/web"
)

// testSecret is a 32-byte secret for testing.
var testSecret = []byte("test-secret-32-bytes-minimum!!!!")

// setupTestServer creates a test server with mock dependencies.
// Returns nil and skips the test if session store cannot be created.
func setupTestServer(t *testing.T) *web.Server {
	t.Helper()

	logger := slog.Default()

	// Create a minimal session store (nil pool is OK for non-transactional tests)
	store := session.New(nil, nil, logger)

	server, err := web.NewServer(web.ServerDeps{
		Logger:       logger,
		SessionStore: store,
		CSRFSecret:   testSecret,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	return server
}

func TestNewServer(t *testing.T) {
	t.Parallel()

	server := setupTestServer(t)
	if server == nil {
		t.Fatal("NewServer returned nil")
	}
}

func TestNewServer_MissingSessionStore(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	_, err := web.NewServer(web.ServerDeps{
		Logger:     logger,
		CSRFSecret: testSecret,
		// SessionStore is nil
	})

	if err == nil {
		t.Error("NewServer should fail with nil SessionStore")
	}
}

func TestNewServer_ShortCSRFSecret(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	store := session.New(nil, nil, logger)

	_, err := web.NewServer(web.ServerDeps{
		Logger:       logger,
		SessionStore: store,
		CSRFSecret:   []byte("too-short"), // Less than 32 bytes
	})

	if err == nil {
		t.Error("NewServer should fail with short CSRFSecret")
	}
}

func TestNewServer_WithNilFlow(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	store := session.New(nil, nil, logger)

	// Explicitly passing nil ChatFlow (simulation mode)
	server, err := web.NewServer(web.ServerDeps{
		Logger:       logger,
		ChatFlow:     nil,
		SessionStore: store,
		CSRFSecret:   testSecret,
	})

	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if server == nil {
		t.Fatal("NewServer returned nil with nil ChatFlow")
	}
}

func TestServer_SecurityHeaders(t *testing.T) {
	t.Parallel()

	server := setupTestServer(t)

	// Use static route to test security headers without needing database
	req := httptest.NewRequest(http.MethodGet, "/genui/static/css/output.css", nil)
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	// Verify Content-Security-Policy
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("missing Content-Security-Policy header")
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Error("CSP missing default-src 'self'")
	}
	if !strings.Contains(csp, "script-src") {
		t.Error("CSP missing script-src directive")
	}
	if !strings.Contains(csp, "connect-src 'self'") {
		t.Error("CSP missing connect-src 'self' for SSE")
	}

	// Verify X-Content-Type-Options
	xcto := rec.Header().Get("X-Content-Type-Options")
	if xcto != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", xcto)
	}

	// Verify X-Frame-Options
	xfo := rec.Header().Get("X-Frame-Options")
	if xfo != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", xfo)
	}

	// Verify Referrer-Policy
	rp := rec.Header().Get("Referrer-Policy")
	if rp == "" {
		t.Error("missing Referrer-Policy header")
	}
}

func TestServer_Routes_Static(t *testing.T) {
	t.Parallel()

	server := setupTestServer(t)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"static css", http.MethodGet, "/genui/static/css/output.css", http.StatusOK},
		{"static js", http.MethodGet, "/genui/static/js/htmx.min.js", http.StatusOK},
		{"static not found", http.MethodGet, "/genui/static/nonexistent.js", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			server.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestServer_Handler(t *testing.T) {
	t.Parallel()

	server := setupTestServer(t)

	handler := server.Handler()
	if handler == nil {
		t.Fatal("Handler() returned nil")
	}
}
