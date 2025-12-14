package web_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/koopa0/koopa-cli/internal/config"
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

	// Create minimal test config
	testCfg := &config.Config{
		ModelName:   "gemini-2.5-flash",
		Temperature: 0.7,
		MaxTokens:   2048,
	}

	server, err := web.NewServer(web.ServerDeps{
		Logger:       logger,
		SessionStore: store,
		CSRFSecret:   testSecret,
		Config:       testCfg,
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
	testCfg := &config.Config{
		ModelName:   "gemini-2.5-flash",
		Temperature: 0.7,
	}
	_, err := web.NewServer(web.ServerDeps{
		Logger:     logger,
		CSRFSecret: testSecret,
		Config:     testCfg,
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
	testCfg := &config.Config{
		ModelName:   "gemini-2.5-flash",
		Temperature: 0.7,
	}

	_, err := web.NewServer(web.ServerDeps{
		Logger:       logger,
		SessionStore: store,
		CSRFSecret:   []byte("too-short"), // Less than 32 bytes
		Config:       testCfg,
	})

	if err == nil {
		t.Error("NewServer should fail with short CSRFSecret")
	}
}

func TestNewServer_WithNilFlow(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	store := session.New(nil, nil, logger)
	testCfg := &config.Config{
		ModelName:   "gemini-2.5-flash",
		Temperature: 0.7,
	}

	// Explicitly passing nil ChatFlow (simulation mode)
	server, err := web.NewServer(web.ServerDeps{
		Logger:       logger,
		ChatFlow:     nil,
		SessionStore: store,
		CSRFSecret:   testSecret,
		Config:       testCfg,
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

// setupTestServerWithDev creates a test server with configurable IsDev mode.
func setupTestServerWithDev(t *testing.T, isDev bool) *web.Server {
	t.Helper()

	logger := slog.Default()
	store := session.New(nil, nil, logger)
	testCfg := &config.Config{
		ModelName:   "gemini-2.5-flash",
		Temperature: 0.7,
		MaxTokens:   2048,
	}

	server, err := web.NewServer(web.ServerDeps{
		Logger:       logger,
		SessionStore: store,
		CSRFSecret:   testSecret,
		Config:       testCfg,
		IsDev:        isDev,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	return server
}

// TestServer_CSPHeader_DevMode verifies that dev mode CSP includes 'unsafe-eval'.
// This is required for debugging tools like axe-core in E2E tests.
func TestServer_CSPHeader_DevMode(t *testing.T) {
	t.Parallel()

	server := setupTestServerWithDev(t, true)

	req := httptest.NewRequest(http.MethodGet, "/genui/static/css/output.css", nil)
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")

	// Dev mode MUST include 'unsafe-eval' for debugging tools
	if !strings.Contains(csp, "'unsafe-eval'") {
		t.Errorf("CSP in dev mode should include 'unsafe-eval', got: %s", csp)
	}

	// Dev mode must still include security basics
	if !strings.Contains(csp, "default-src 'self'") {
		t.Error("CSP missing default-src 'self' in dev mode")
	}

	// Verify other required directives still present
	if !strings.Contains(csp, "script-src") {
		t.Error("CSP missing script-src directive in dev mode")
	}
}

// TestServer_CSPHeader_ProdMode verifies that production CSP does NOT include 'unsafe-eval'.
// This ensures stricter security in production environments.
func TestServer_CSPHeader_ProdMode(t *testing.T) {
	t.Parallel()

	server := setupTestServerWithDev(t, false)

	req := httptest.NewRequest(http.MethodGet, "/genui/static/css/output.css", nil)
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")

	// Production MUST NOT include 'unsafe-eval'
	if strings.Contains(csp, "'unsafe-eval'") {
		t.Errorf("CSP in production should NOT include 'unsafe-eval', got: %s", csp)
	}

	// Verify production has all required directives
	requiredDirectives := []string{
		"default-src 'self'",
		"script-src 'self' 'unsafe-inline'",
		"style-src 'self' 'unsafe-inline'",
		"connect-src 'self'",
	}

	for _, directive := range requiredDirectives {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP missing %q in production mode", directive)
		}
	}
}
