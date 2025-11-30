//go:build !dev

package static

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedAssets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path         string
		minSize      int64
		contentCheck string // Substring to verify content
	}{
		{"css/app.css", 50, "@tailwind"},
		{"css/output.css", 100, ""},
		{"js/htmx.min.js", 1000, "htmx"},
		{"js/htmx-sse.js", 100, ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()

			f, err := assetsFS.Open(tt.path)
			if err != nil {
				t.Fatalf("failed to open %s: %v", tt.path, err)
			}
			defer f.Close()

			stat, err := f.Stat()
			if err != nil {
				t.Fatalf("failed to stat %s: %v", tt.path, err)
			}

			if stat.Size() < tt.minSize {
				t.Errorf("%s size %d < minimum %d", tt.path, stat.Size(), tt.minSize)
			}

			if tt.contentCheck != "" {
				content, err := io.ReadAll(f)
				if err != nil {
					t.Fatalf("failed to read %s: %v", tt.path, err)
				}
				if !strings.Contains(string(content), tt.contentCheck) {
					t.Errorf("%s missing expected content marker %q", tt.path, tt.contentCheck)
				}
			}
		})
	}
}

func TestHandler(t *testing.T) {
	t.Parallel()

	h := Handler()
	if h == nil {
		t.Fatal("Handler() returned nil")
	}
}

func TestHandler_ServeEmbeddedAssets(t *testing.T) {
	t.Parallel()

	handler := Handler()

	tests := []struct {
		name       string
		path       string
		wantStatus int
		wantType   string // Content-Type prefix
	}{
		{"CSS file", "/css/output.css", http.StatusOK, "text/css"},
		{"JS file", "/js/htmx.min.js", http.StatusOK, ""},
		{"Not found", "/nonexistent.js", http.StatusNotFound, ""},
		{"Directory traversal blocked", "/../../../etc/passwd", http.StatusNotFound, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if tt.wantType != "" {
				contentType := rec.Header().Get("Content-Type")
				if !strings.HasPrefix(contentType, tt.wantType) {
					t.Errorf("Content-Type = %q, want prefix %q", contentType, tt.wantType)
				}
			}
		})
	}
}

// TestProductionBuild verifies this test only runs in production mode.
// The //go:build !dev tag ensures this test is skipped in dev mode.
func TestProductionBuild(t *testing.T) {
	t.Log("Verified: Running production build with embedded assets")
}
