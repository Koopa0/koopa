package web_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/koopa0/koopa-cli/internal/ui/web"
)

func TestNewServer(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	server := web.NewServer(web.ServerDeps{Logger: logger})

	if server == nil {
		t.Fatal("NewServer returned nil")
	}
}

func TestNewServer_WithNilFlow(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	// Explicitly passing nil ChatFlow (simulation mode)
	server := web.NewServer(web.ServerDeps{
		Logger:   logger,
		ChatFlow: nil,
	})

	if server == nil {
		t.Fatal("NewServer returned nil with nil ChatFlow")
	}
}

func TestServer_SecurityHeaders(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	server := web.NewServer(web.ServerDeps{Logger: logger})

	req := httptest.NewRequest(http.MethodGet, "/genui", nil)
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

func TestServer_Routes(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	server := web.NewServer(web.ServerDeps{Logger: logger})

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"chat page", http.MethodGet, "/genui", http.StatusOK},
		{"chat page trailing slash", http.MethodGet, "/genui/", http.StatusOK},
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

	logger := slog.Default()
	server := web.NewServer(web.ServerDeps{Logger: logger})

	handler := server.Handler()
	if handler == nil {
		t.Fatal("Handler() returned nil")
	}

	// Verify handler is usable
	req := httptest.NewRequest(http.MethodGet, "/genui", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}
