package sse_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/a-h/templ"
	"github.com/koopa0/koopa-cli/internal/web/sse"
)

func TestNewWriter(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}
	if sseWriter == nil {
		t.Fatal("writer is nil")
	}

	// Check headers
	headers := w.Header()
	if got := headers.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}
	if got := headers.Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}
	if got := headers.Get("Connection"); got != "keep-alive" {
		t.Errorf("Connection = %q, want keep-alive", got)
	}
}

// noFlushWriter is a ResponseWriter that does NOT implement http.Flusher.
type noFlushWriter struct {
	header http.Header
}

func (w *noFlushWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (*noFlushWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (*noFlushWriter) WriteHeader(int) {}

func TestNewWriter_NoFlusher(t *testing.T) {
	t.Parallel()

	w := &noFlushWriter{}
	_, err := sse.NewWriter(w)

	if err == nil {
		t.Error("expected error for non-Flusher ResponseWriter")
	}

	if !strings.Contains(err.Error(), "does not support flusher interface") {
		t.Errorf("wrong error message: %v", err)
	}
}

func TestWriter_WriteChunk(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	ctx := context.Background()
	err = sseWriter.WriteChunk(ctx, "test-123", "Hello world")
	if err != nil {
		t.Fatalf("WriteChunk failed: %v", err)
	}

	body := w.Body.String()

	// Check SSE format
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing 'event: chunk' in response")
	}
	if !strings.Contains(body, "data: ") {
		t.Error("missing 'data:' in response")
	}
	if !strings.Contains(body, "msg-content-test-123") {
		t.Error("missing message ID in response")
	}
	if !strings.Contains(body, "Hello world") {
		t.Error("missing content in response")
	}
	if !strings.Contains(body, "hx-swap-oob") {
		t.Error("missing OOB swap attribute")
	}
}

func TestWriter_WriteChunk_ContextCanceled(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = sseWriter.WriteChunk(ctx, "test-123", "Hello")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestWriter_WriteError(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	err = sseWriter.WriteError("test_error", "Something went wrong")
	if err != nil {
		t.Fatalf("WriteError failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "event: error") {
		t.Error("missing 'event: error' in response")
	}
	if !strings.Contains(body, "test_error") {
		t.Error("missing error code in response")
	}
	if !strings.Contains(body, "Something went wrong") {
		t.Error("missing error message in response")
	}
}

func TestWriter_WriteEvent(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Create a simple component for testing
	comp := templ.Raw("<div>Test Content</div>")

	ctx := context.Background()
	err = sseWriter.WriteEvent(ctx, "done", comp)
	if err != nil {
		t.Fatalf("WriteEvent failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "event: done") {
		t.Error("missing 'event: done' in response")
	}
	if !strings.Contains(body, "Test Content") {
		t.Error("missing component content in response")
	}
}

func TestWriter_WriteChunk_XSSPrevention(t *testing.T) {
	t.Parallel()

	xssPayloads := []struct {
		name       string
		payload    string
		mustEscape string
	}{
		{
			name:       "script tag",
			payload:    "<script>alert('xss')</script>",
			mustEscape: "<script>",
		},
		{
			name:       "img with onerror",
			payload:    `<img src=x onerror="alert('xss')">`,
			mustEscape: "<img",
		},
		{
			name:       "javascript URL",
			payload:    `<a href="javascript:alert('xss')">click</a>`,
			mustEscape: "<a href",
		},
		{
			name:       "svg onload",
			payload:    `<svg/onload=alert('xss')>`,
			mustEscape: "<svg",
		},
	}

	for _, tt := range xssPayloads {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			sseWriter, err := sse.NewWriter(w)
			if err != nil {
				t.Fatalf("NewWriter failed: %v", err)
			}

			ctx := context.Background()
			err = sseWriter.WriteChunk(ctx, "test-msg", tt.payload)
			if err != nil {
				t.Fatalf("WriteChunk failed: %v", err)
			}

			body := w.Body.String()

			// Verify raw HTML tag is NOT present (would execute as HTML)
			if strings.Contains(body, tt.mustEscape) {
				t.Errorf("XSS payload not escaped: found raw %q in response", tt.mustEscape)
			}

			// Verify escaped version IS present (raw HTML, not JSON-encoded)
			// html.EscapeString converts < to &lt; and > to &gt;
			escapedOpen := strings.ReplaceAll(tt.mustEscape, "<", "&lt;")
			escapedOpen = strings.ReplaceAll(escapedOpen, ">", "&gt;")
			if !strings.Contains(body, escapedOpen) {
				t.Errorf("expected escaped content %q in response, got: %s", escapedOpen, body)
			}
		})
	}
}

func TestWriter_WriteChunk_RawHTMLFormat(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	ctx := context.Background()
	err = sseWriter.WriteChunk(ctx, "test-123", "Hello world")
	if err != nil {
		t.Fatalf("WriteChunk failed: %v", err)
	}

	body := w.Body.String()

	// Verify SSE format with raw HTML (no JSON wrapper)
	// Format should be:
	// event: chunk
	// data: <div id="msg-content-test-123" hx-swap-oob="innerHTML">Hello world</div>
	//
	// (empty line)

	// Should NOT contain JSON markers
	if strings.Contains(body, `{"html":`) {
		t.Error("response contains JSON wrapper - HTMX SSE expects raw HTML")
	}

	// Should contain raw HTML directly after "data: "
	if !strings.Contains(body, "data: <div") {
		t.Error("expected raw HTML after 'data: ', not JSON")
	}
}

func TestWriter_WriteChunk_MultilineContent(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	ctx := context.Background()
	// Content with newline (simulates multi-line HTML)
	err = sseWriter.WriteChunk(ctx, "test-123", "Line1\nLine2")
	if err != nil {
		t.Fatalf("WriteChunk failed: %v", err)
	}

	body := w.Body.String()

	// SSE spec: each line needs "data: " prefix
	// The HTML itself contains the escaped newline within the content
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing event: chunk")
	}
	if !strings.Contains(body, "data:") {
		t.Error("missing data: prefix")
	}
}

func TestWriter_WriteChunkRaw(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	ctx := context.Background()
	// Pre-escaped content (caller's responsibility)
	preEscaped := "&lt;script&gt;alert('safe')&lt;/script&gt;"
	err = sseWriter.WriteChunkRaw(ctx, "test-456", preEscaped)
	if err != nil {
		t.Fatalf("WriteChunkRaw failed: %v", err)
	}

	body := w.Body.String()

	// Verify SSE format
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing 'event: chunk' in response")
	}
	if !strings.Contains(body, "msg-content-test-456") {
		t.Error("missing message ID in response")
	}
	// Content should NOT be double-escaped
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("pre-escaped content should be preserved")
	}
	// Should NOT contain double-escaped entities
	if strings.Contains(body, "&amp;lt;") {
		t.Error("content was double-escaped - WriteChunkRaw should not escape")
	}
	if !strings.Contains(body, "hx-swap-oob") {
		t.Error("missing OOB swap attribute")
	}
}

func TestWriter_WriteChunkRaw_ContextCanceled(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = sseWriter.WriteChunkRaw(ctx, "test-123", "content")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestWriter_WriteDone(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Create a component with OOB swap (simulates final message)
	comp := templ.Raw(`<article id="msg-final" hx-swap-oob="outerHTML">Final message</article>`)

	ctx := context.Background()
	err = sseWriter.WriteDone(ctx, comp)
	if err != nil {
		t.Fatalf("WriteDone failed: %v", err)
	}

	body := w.Body.String()

	// Verify SSE format with 'done' event
	if !strings.Contains(body, "event: done") {
		t.Error("missing 'event: done' in response")
	}
	if !strings.Contains(body, "msg-final") {
		t.Error("missing message ID in response")
	}
	if !strings.Contains(body, "hx-swap-oob") {
		t.Error("missing OOB swap attribute for final message")
	}
	if !strings.Contains(body, "Final message") {
		t.Error("missing final message content")
	}
	// Should be raw HTML, not JSON
	if strings.Contains(body, `{"html":`) {
		t.Error("WriteDone should send raw HTML, not JSON")
	}
}
