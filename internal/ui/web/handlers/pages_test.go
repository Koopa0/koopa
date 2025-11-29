package handlers_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/koopa0/koopa-cli/internal/ui/web/handlers"
)

func TestPages_Chat(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	handler := handlers.NewPages(logger)

	req := httptest.NewRequest(http.MethodGet, "/genui", nil)
	rec := httptest.NewRecorder()

	handler.Chat(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify page structure (templ outputs lowercase doctype)
	if !strings.Contains(strings.ToLower(body), "<!doctype html>") {
		t.Errorf("missing DOCTYPE declaration, got: %s", body[:min(200, len(body))])
	}

	if !strings.Contains(body, "<html") {
		t.Error("missing html tag")
	}

	// Verify HTMX is loaded
	if !strings.Contains(body, "htmx") {
		t.Error("missing htmx reference")
	}

	// Verify chat form exists
	if !strings.Contains(body, "hx-post") {
		t.Error("missing HTMX form submission")
	}

	// Verify message list container exists
	if !strings.Contains(body, "message-list") {
		t.Error("missing message-list container")
	}
}

func TestNewPages(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	handler := handlers.NewPages(logger)

	if handler == nil {
		t.Fatal("NewPages returned nil")
	}
}
