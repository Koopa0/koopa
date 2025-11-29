package handlers_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/koopa0/koopa-cli/internal/ui/web/handlers"
)

func TestChat_Send(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	handler := handlers.NewChat(logger, nil) // nil flow = simulation mode

	tests := []struct {
		name       string
		content    string
		sessionID  string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "valid message",
			content:    "Hello World",
			sessionID:  "test-session",
			wantStatus: http.StatusOK,
		},
		{
			name:       "empty content",
			content:    "",
			sessionID:  "test-session",
			wantStatus: http.StatusBadRequest,
			wantBody:   "content is required",
		},
		{
			name:       "whitespace only content",
			content:    "   \n\t  ",
			sessionID:  "test-session",
			wantStatus: http.StatusBadRequest,
			wantBody:   "content is required",
		},
		{
			name:       "missing sessionId uses default",
			content:    "Hello",
			sessionID:  "",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			form := url.Values{}
			form.Set("content", tt.content)
			if tt.sessionID != "" {
				form.Set("sessionId", tt.sessionID)
			}

			req := httptest.NewRequest(http.MethodPost, "/genui/chat/send",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			handler.Send(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if tt.wantBody != "" && !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want to contain %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestChat_Send_XSSPrevention(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	handler := handlers.NewChat(logger, nil) // nil flow = simulation mode

	// XSS payloads that should be escaped by templ.
	// templ uses HTML entity encoding, so we verify the raw HTML tag doesn't appear.
	xssPayloads := []struct {
		name       string
		payload    string
		mustEscape string // This exact string should be escaped (replaced with entities)
	}{
		{
			name:       "script tag",
			payload:    "<script>alert('xss')</script>",
			mustEscape: "<script>", // Should become &lt;script&gt;
		},
		{
			name:       "img tag with event",
			payload:    `<img src=x onerror="alert('xss')">`,
			mustEscape: "<img", // Should become &lt;img
		},
		{
			name:       "anchor with javascript",
			payload:    `<a href="javascript:alert('xss')">click</a>`,
			mustEscape: "<a href", // Should become &lt;a href
		},
		{
			name:       "svg tag",
			payload:    `<svg/onload=alert('xss')>`,
			mustEscape: "<svg", // Should become &lt;svg
		},
	}

	for _, tt := range xssPayloads {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			form := url.Values{}
			form.Set("content", tt.payload)
			form.Set("sessionId", "test-session")

			req := httptest.NewRequest(http.MethodPost, "/genui/chat/send",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			handler.Send(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}

			body := rec.Body.String()

			// Verify raw HTML tag is NOT present (would execute as HTML)
			if strings.Contains(body, tt.mustEscape) {
				t.Errorf("XSS payload not escaped: found raw %q in response", tt.mustEscape)
			}

			// Verify the escaped version IS present (templ uses &lt; etc.)
			escapedVersion := strings.ReplaceAll(tt.mustEscape, "<", "&lt;")
			escapedVersion = strings.ReplaceAll(escapedVersion, ">", "&gt;")
			if !strings.Contains(body, escapedVersion) && !strings.Contains(body, "&#") {
				t.Logf("Note: escaped content might use different encoding")
			}
		})
	}
}

func TestChat_Stream_ParameterValidation(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	handler := handlers.NewChat(logger, nil) // nil flow = simulation mode

	tests := []struct {
		name       string
		msgID      string
		sessionID  string
		query      string
		wantStatus int
	}{
		{
			name:       "missing msgId",
			msgID:      "",
			sessionID:  "sess",
			query:      "hello",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing sessionId",
			msgID:      "msg123",
			sessionID:  "",
			query:      "hello",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing query",
			msgID:      "msg123",
			sessionID:  "sess",
			query:      "",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			params := url.Values{}
			if tt.msgID != "" {
				params.Set("msgId", tt.msgID)
			}
			if tt.sessionID != "" {
				params.Set("sessionId", tt.sessionID)
			}
			if tt.query != "" {
				params.Set("query", tt.query)
			}

			urlStr := "/genui/stream"
			if len(params) > 0 {
				urlStr += "?" + params.Encode()
			}

			req := httptest.NewRequest(http.MethodGet, urlStr, nil)
			rec := httptest.NewRecorder()

			handler.Stream(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestNewChat(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	handler := handlers.NewChat(logger, nil) // nil flow = simulation mode

	if handler == nil {
		t.Fatal("NewChat returned nil")
	}
}

func TestNewChat_NilLogger_Panics(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Error("NewChat with nil logger should panic")
		}
	}()

	handlers.NewChat(nil, nil)
}

func TestNewChat_NilFlow_SimulationMode(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	// nil flow should work (simulation mode)
	handler := handlers.NewChat(logger, nil)

	if handler == nil {
		t.Fatal("NewChat with nil flow should work (simulation mode)")
	}
}

func TestChat_Stream_SimulationMode(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	handler := handlers.NewChat(logger, nil) // nil flow = simulation mode

	params := url.Values{}
	params.Set("msgId", "test-msg-123")
	params.Set("sessionId", "test-session")
	params.Set("query", "Hello AI")

	req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
	rec := httptest.NewRecorder()

	handler.Stream(rec, req)

	// Verify SSE response format
	body := rec.Body.String()

	// Check Content-Type is SSE
	if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}

	// Check for chunk events
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing 'event: chunk' in response")
	}

	// Check for done event
	if !strings.Contains(body, "event: done") {
		t.Error("missing 'event: done' in response")
	}

	// Check OOB swap is present for streaming updates
	if !strings.Contains(body, "hx-swap-oob") {
		t.Error("missing OOB swap attribute in response")
	}

	// Check message content target ID
	if !strings.Contains(body, "msg-content-test-msg-123") {
		t.Error("missing message content target ID")
	}

	// Check that response includes part of the query (simulation echoes it)
	if !strings.Contains(body, "Hello AI") {
		t.Error("simulated response should reference the query")
	}
}

func TestChat_Stream_SimulationMode_XSSPrevention(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	handler := handlers.NewChat(logger, nil) // nil flow = simulation mode

	// XSS payload in query - should be escaped in simulated response
	params := url.Values{}
	params.Set("msgId", "test-xss")
	params.Set("sessionId", "test-session")
	params.Set("query", "<script>alert('xss')</script>")

	req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
	rec := httptest.NewRecorder()

	handler.Stream(rec, req)

	body := rec.Body.String()

	// Verify raw script tag is NOT present (would execute as HTML)
	if strings.Contains(body, "<script>") {
		t.Error("XSS payload not escaped: found raw <script> in response")
	}
}
