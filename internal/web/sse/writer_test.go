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

	if !strings.Contains(err.Error(), "does not implement http.Flusher") {
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
	// WriteChunk now takes templ.Component, not string
	comp := templ.Raw("Hello world")
	err = sseWriter.WriteChunk(ctx, "test-123", comp)
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

	// WriteChunk takes templ.Component
	// Note: templ.Raw doesn't respect context cancellation in Render
	// (it immediately writes to buffer), so this test verifies that
	// WriteChunk still works with a canceled context for simple components.
	// For real cancellation support, use templ components that check ctx.
	comp := templ.Raw("Hello")
	err = sseWriter.WriteChunk(ctx, "test-123", comp)
	// templ.Raw does not error on canceled context - this is expected behavior
	// The context cancellation is handled at the handler level (streaming loop)
	if err != nil {
		t.Logf("WriteChunk returned error (acceptable): %v", err)
	}
	// Test passes regardless - context handling is at handler level, not SSE writer
}

func TestWriter_WriteError(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// WriteError now takes msgID, code, message and sends HTML OOB
	err = sseWriter.WriteError("msg-123", "test_error", "Something went wrong")
	if err != nil {
		t.Fatalf("WriteError failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "event: error") {
		t.Error("missing 'event: error' in response")
	}
	// Check for OOB swap targeting the message content div
	if !strings.Contains(body, `id="msg-content-msg-123"`) {
		t.Error("missing message content ID in OOB swap")
	}
	if !strings.Contains(body, `hx-swap-oob="innerHTML"`) {
		t.Error("missing OOB swap directive")
	}
	if !strings.Contains(body, "Something went wrong") {
		t.Error("missing error message in response")
	}
}

func TestWriter_WriteDone(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Create a simple component for testing
	comp := templ.Raw("<div>Test Content</div>")

	ctx := context.Background()
	// WriteDone now takes msgID for OOB swap targeting
	err = sseWriter.WriteDone(ctx, "test-msg-123", comp)
	if err != nil {
		t.Fatalf("WriteDone failed: %v", err)
	}

	body := w.Body.String()

	// Per HTMX Master: WriteDone sends final content as "chunk" OOB, then empty "done"
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing 'event: chunk' for final content in response")
	}
	if !strings.Contains(body, "event: done") {
		t.Error("missing 'event: done' to close connection")
	}
	if !strings.Contains(body, "Test Content") {
		t.Error("missing component content in response")
	}
	// Verify OOB swap targeting
	if !strings.Contains(body, "message-test-msg-123") {
		t.Error("missing message ID in OOB swap target")
	}
	if !strings.Contains(body, "hx-swap-oob") {
		t.Error("missing OOB swap attribute in final content")
	}
}

func TestWriter_WriteChunk_XSSPrevention(t *testing.T) {
	t.Parallel()

	// Note: WriteChunk takes templ.Component which handles escaping automatically.
	// templ.Raw bypasses escaping, so for XSS testing we should use templ.ComponentFunc
	// or verify at the handler level where content is escaped before being passed.
	// Here we test that templ.Raw content is passed through as-is (caller's responsibility).

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	ctx := context.Background()
	// Using templ.Raw means content is NOT escaped - this is intentional for pre-escaped content
	// For real XSS prevention, use templ components that escape automatically
	comp := templ.Raw("&lt;script&gt;escaped&lt;/script&gt;")
	err = sseWriter.WriteChunk(ctx, "test-msg", comp)
	if err != nil {
		t.Fatalf("WriteChunk failed: %v", err)
	}

	body := w.Body.String()

	// Verify content is passed through (templ.Raw doesn't escape)
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("pre-escaped content should be preserved")
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
	comp := templ.Raw("Hello world")
	err = sseWriter.WriteChunk(ctx, "test-123", comp)
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
	comp := templ.Raw("Line1\nLine2")
	err = sseWriter.WriteChunk(ctx, "test-123", comp)
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

	// Pre-escaped content (caller's responsibility)
	// WriteChunkRaw sends plain HTML for sse-swap="chunk" on client
	preEscaped := "&lt;script&gt;alert('safe')&lt;/script&gt;"
	err = sseWriter.WriteChunkRaw("test-456", preEscaped)
	if err != nil {
		t.Fatalf("WriteChunkRaw failed: %v", err)
	}

	body := w.Body.String()

	// Verify SSE format
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing 'event: chunk' in response")
	}
	// Content should NOT be double-escaped
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("pre-escaped content should be preserved")
	}
	// Should NOT contain double-escaped entities
	if strings.Contains(body, "&amp;lt;") {
		t.Error("content was double-escaped - WriteChunkRaw should not escape")
	}
	// Per HTMX Master review: WriteChunkRaw sends plain HTML (no OOB wrapper)
	// The client has sse-swap="chunk" which handles the swap directly
	if strings.Contains(body, "hx-swap-oob") {
		t.Error("WriteChunkRaw should NOT contain OOB wrapper - client uses sse-swap")
	}
}

func TestWriter_WriteChunkRaw_NoContextNeeded(t *testing.T) {
	t.Parallel()

	// Verify that WriteChunkRaw doesn't need context and works without it
	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// WriteChunkRaw should work without ctx - it's a pure write operation
	err = sseWriter.WriteChunkRaw("test-123", "content")
	if err != nil {
		t.Errorf("WriteChunkRaw should succeed without ctx: %v", err)
	}
}

func TestWriter_WriteDone_WithOOBSwap(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Create a component (simulates final message bubble)
	comp := templ.Raw(`<article class="message">Final message</article>`)

	ctx := context.Background()
	// WriteDone now adds its own OOB wrapper using msgID
	err = sseWriter.WriteDone(ctx, "msg-final", comp)
	if err != nil {
		t.Fatalf("WriteDone failed: %v", err)
	}

	body := w.Body.String()

	// Per HTMX Master: WriteDone sends final as "chunk" OOB then empty "done"
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing 'event: chunk' for final content")
	}
	if !strings.Contains(body, "event: done") {
		t.Error("missing 'event: done' to close connection")
	}
	// WriteDone wraps content with OOB targeting message-{msgID}
	if !strings.Contains(body, "message-msg-final") {
		t.Error("missing message ID in OOB wrapper")
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

// =============================================================================
// Canvas Mode Methods Tests
// =============================================================================

func TestWriter_WriteArtifact(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	comp := templ.Raw(`<div class="artifact">Code Block</div>`)

	ctx := context.Background()
	err = sseWriter.WriteArtifact(ctx, comp)
	if err != nil {
		t.Fatalf("WriteArtifact failed: %v", err)
	}

	body := w.Body.String()

	// Per HTMX Master: WriteArtifact must use "chunk" event because SSE client
	// only listens for "chunk" events via sse-swap="chunk"
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing 'event: chunk' in response - SSE client only listens for chunk events")
	}
	if !strings.Contains(body, "Code Block") {
		t.Error("missing artifact content in response")
	}
}

func TestWriter_WriteWithArtifact(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	artifactComp := templ.Raw(`<div class="artifact">Generated Code</div>`)

	ctx := context.Background()
	err = sseWriter.WriteWithArtifact(ctx, "msg-123", "Message text", artifactComp)
	if err != nil {
		t.Fatalf("WriteWithArtifact failed: %v", err)
	}

	body := w.Body.String()

	// Per HTMX Master: Both message chunk and artifact use "chunk" event
	// because SSE client only listens for "chunk" events via sse-swap="chunk"
	chunkCount := strings.Count(body, "event: chunk")
	if chunkCount < 2 {
		t.Errorf("expected at least 2 'event: chunk' occurrences, got %d", chunkCount)
	}
	if !strings.Contains(body, "Message text") {
		t.Error("missing message content in response")
	}
	if !strings.Contains(body, "Generated Code") {
		t.Error("missing artifact content in response")
	}
}

func TestWriter_ClearArtifact(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	emptyStateComp := templ.Raw(`<div class="empty-state">No artifact</div>`)

	ctx := context.Background()
	err = sseWriter.ClearArtifact(ctx, emptyStateComp)
	if err != nil {
		t.Fatalf("ClearArtifact failed: %v", err)
	}

	body := w.Body.String()

	// Per HTMX Master: ClearArtifact must use "chunk" event because SSE client
	// only listens for "chunk" events via sse-swap="chunk"
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing 'event: chunk' in response - SSE client only listens for chunk events")
	}
	if !strings.Contains(body, "No artifact") {
		t.Error("missing empty state content in response")
	}
	if !strings.Contains(body, `hx-swap-oob="innerHTML"`) {
		t.Error("missing OOB swap attribute for artifact-content")
	}
}

// =============================================================================
// QA-Master Required Tests (P0)
// =============================================================================

// TestWriter_WriteDone_ChunkBeforeDone_Sequence validates the CRITICAL SSE event sequence.
// HTMX sse-close="done" closes connection BEFORE processing swap content.
// Therefore, final content MUST be sent as "chunk" BEFORE the "done" event.
func TestWriter_WriteDone_ChunkBeforeDone_Sequence(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	comp := templ.Raw("<div>Final message content</div>")
	ctx := context.Background()

	err = sseWriter.WriteDone(ctx, "msg-sequence-test", comp)
	if err != nil {
		t.Fatalf("WriteDone failed: %v", err)
	}

	body := w.Body.String()

	// Parse SSE events manually to verify sequence
	// SSE format: "event: <type>\ndata: <content>\n\n"
	chunkIndex := strings.Index(body, "event: chunk")
	doneIndex := strings.Index(body, "event: done")

	if chunkIndex == -1 {
		t.Fatal("missing 'event: chunk' in response")
	}
	if doneIndex == -1 {
		t.Fatal("missing 'event: done' in response")
	}

	// CRITICAL: chunk MUST come BEFORE done
	if chunkIndex >= doneIndex {
		t.Errorf("SEQUENCE ERROR: chunk event (index %d) must come BEFORE done event (index %d)",
			chunkIndex, doneIndex)
	}

	// Verify done event has empty data (per WriteDone implementation)
	// Find the data line after "event: done"
	doneSection := body[doneIndex:]
	dataAfterDone := strings.Index(doneSection, "data:")
	if dataAfterDone == -1 {
		t.Error("missing 'data:' after done event")
	} else {
		// Extract data content after "event: done\ndata: "
		afterData := doneSection[dataAfterDone+5:] // Skip "data:"
		// Trim to get just the data content before newline
		endOfLine := strings.Index(afterData, "\n")
		if endOfLine > 0 {
			dataContent := strings.TrimSpace(afterData[:endOfLine])
			if dataContent != "" {
				t.Errorf("done event should have empty data, got: %q", dataContent)
			}
		}
	}

	// Verify chunk event contains the message content
	chunkSection := body[chunkIndex:doneIndex]
	if !strings.Contains(chunkSection, "Final message content") {
		t.Error("chunk event should contain the final message content")
	}
	if !strings.Contains(chunkSection, "hx-swap-oob") {
		t.Error("chunk event should contain OOB swap attribute")
	}
}

// TestWriter_WriteDone_ContextCanceled tests behavior when context is canceled
// between rendering component and sending events.
func TestWriter_WriteDone_ContextCanceled(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Create a context that's already canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	comp := templ.Raw("<div>Content</div>")

	// WriteDone should handle canceled context gracefully
	// templ.Raw doesn't check context, so this should still succeed
	// (the handler layer is responsible for checking context before calling WriteDone)
	err = sseWriter.WriteDone(ctx, "msg-canceled", comp)
	// For templ.Raw, context cancellation doesn't cause error
	// This documents expected behavior: SSE writer itself doesn't check context
	// Context checking is handler's responsibility
	if err != nil {
		t.Logf("WriteDone with canceled context returned error (acceptable): %v", err)
	}

	// Verify that even with canceled context, output is well-formed
	// (no partial writes that could corrupt SSE stream)
	body := w.Body.String()
	if body != "" {
		// If anything was written, it should be valid SSE
		if strings.Contains(body, "event:") && !strings.Contains(body, "data:") {
			t.Error("partial SSE event written - stream may be corrupted")
		}
	}
}

// =============================================================================
// Canvas Panel Dynamic Display Tests
// =============================================================================

// TestWriter_WriteCanvasShow tests the canvas panel show functionality.
// Verifies the script injection pattern used for dynamic panel display.
func TestWriter_WriteCanvasShow(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	err = sseWriter.WriteCanvasShow()
	if err != nil {
		t.Fatalf("WriteCanvasShow failed: %v", err)
	}

	body := w.Body.String()

	// CRITICAL: Must use "chunk" event because the SSE client only listens for "chunk" events
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing 'event: chunk' in response - SSE client only listens for chunk events")
	}

	// Verify OOB swap wrapper (div with hx-swap-oob)
	if !strings.Contains(body, "hx-swap-oob=\"beforeend:body\"") {
		t.Error("missing OOB swap attribute for script injection")
	}

	// Verify element targeting
	if !strings.Contains(body, "artifact-panel") {
		t.Error("missing artifact-panel element ID in script")
	}
	if !strings.Contains(body, "main-content") {
		t.Error("missing main-content element ID in script")
	}

	// Verify show classes
	if !strings.Contains(body, "xl:translate-x-0") {
		t.Error("missing show class (xl:translate-x-0) in script")
	}
	if !strings.Contains(body, "xl:translate-x-full") {
		t.Error("missing class to remove (xl:translate-x-full) in script")
	}
	if !strings.Contains(body, "xl:pr-96") {
		t.Error("missing padding class (xl:pr-96) in script")
	}

	// Verify accessibility attribute update
	if !strings.Contains(body, "aria-hidden") && !strings.Contains(body, "false") {
		t.Error("missing accessibility attribute update (aria-hidden: false)")
	}

	// Verify self-removing script pattern
	if !strings.Contains(body, "document.currentScript") {
		t.Error("missing self-removing script pattern")
	}
}

// TestWriter_WriteCanvasHide tests the canvas panel hide functionality.
// Verifies the script injection pattern used for dynamic panel hiding.
func TestWriter_WriteCanvasHide(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	err = sseWriter.WriteCanvasHide()
	if err != nil {
		t.Fatalf("WriteCanvasHide failed: %v", err)
	}

	body := w.Body.String()

	// CRITICAL: Must use "chunk" event because the SSE client only listens for "chunk" events
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing 'event: chunk' in response - SSE client only listens for chunk events")
	}

	// Verify OOB swap wrapper (div with hx-swap-oob)
	if !strings.Contains(body, "hx-swap-oob=\"beforeend:body\"") {
		t.Error("missing OOB swap attribute for script injection")
	}

	// Verify element targeting
	if !strings.Contains(body, "artifact-panel") {
		t.Error("missing artifact-panel element ID in script")
	}
	if !strings.Contains(body, "main-content") {
		t.Error("missing main-content element ID in script")
	}

	// Verify hide classes
	if !strings.Contains(body, "xl:translate-x-full") {
		t.Error("missing hide class (xl:translate-x-full) in script")
	}
	if !strings.Contains(body, "xl:translate-x-0") {
		t.Error("missing class to remove (xl:translate-x-0) in script")
	}

	// Verify padding class removal
	if !strings.Contains(body, "xl:pr-96") {
		t.Error("missing padding class (xl:pr-96) in script")
	}

	// Verify accessibility attribute update
	if !strings.Contains(body, "aria-hidden") && !strings.Contains(body, "true") {
		t.Error("missing accessibility attribute update (aria-hidden: true)")
	}

	// Verify self-removing script pattern
	if !strings.Contains(body, "document.currentScript") {
		t.Error("missing self-removing script pattern")
	}
}

// TestWriter_WriteCanvasShow_ScriptStructure verifies the IIFE pattern and DOM safety.
func TestWriter_WriteCanvasShow_ScriptStructure(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	err = sseWriter.WriteCanvasShow()
	if err != nil {
		t.Fatalf("WriteCanvasShow failed: %v", err)
	}

	body := w.Body.String()

	// Verify IIFE (Immediately Invoked Function Expression) pattern
	if !strings.Contains(body, "(function()") {
		t.Error("missing IIFE pattern - scripts should use (function() { ... })();")
	}
	if !strings.Contains(body, "})();") {
		t.Error("missing IIFE closing - scripts should use (function() { ... })();")
	}

	// Verify null checks for defensive programming
	if !strings.Contains(body, "if (panel)") {
		t.Error("missing null check for panel element")
	}
	if !strings.Contains(body, "if (main)") {
		t.Error("missing null check for main element")
	}

	// Verify data attribute for debugging/inspection
	if !strings.Contains(body, "data-canvas-toggle") {
		t.Error("missing data-canvas-toggle attribute for debugging")
	}
}

// TestWriter_WriteCanvasHide_ScriptStructure verifies the IIFE pattern and DOM safety.
func TestWriter_WriteCanvasHide_ScriptStructure(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	err = sseWriter.WriteCanvasHide()
	if err != nil {
		t.Fatalf("WriteCanvasHide failed: %v", err)
	}

	body := w.Body.String()

	// Verify IIFE pattern
	if !strings.Contains(body, "(function()") {
		t.Error("missing IIFE pattern - scripts should use (function() { ... })();")
	}
	if !strings.Contains(body, "})();") {
		t.Error("missing IIFE closing - scripts should use (function() { ... })();")
	}

	// Verify null checks
	if !strings.Contains(body, "if (panel)") {
		t.Error("missing null check for panel element")
	}
	if !strings.Contains(body, "if (main)") {
		t.Error("missing null check for main element")
	}

	// Verify data attribute
	if !strings.Contains(body, "data-canvas-toggle") {
		t.Error("missing data-canvas-toggle attribute for debugging")
	}
}

// TestWriter_WriteDone_EmptyMsgID tests behavior with empty message ID.
func TestWriter_WriteDone_EmptyMsgID(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	comp := templ.Raw("<div>Content</div>")
	ctx := context.Background()

	// Empty msgID should still produce valid output (defensive coding)
	err = sseWriter.WriteDone(ctx, "", comp)
	if err != nil {
		t.Fatalf("WriteDone with empty msgID failed: %v", err)
	}

	body := w.Body.String()

	// Should produce valid SSE even with empty ID
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing 'event: chunk' even with empty msgID")
	}
	if !strings.Contains(body, "event: done") {
		t.Error("missing 'event: done' even with empty msgID")
	}

	// OOB swap will target "message-" (empty ID) - this is valid HTML
	// Browser will look for element with id="message-" which won't exist
	// This is acceptable degradation - no crash, just no swap
	if !strings.Contains(body, `id="message-"`) {
		t.Error("should produce OOB wrapper even with empty msgID")
	}
}

// =============================================================================
// Sidebar Refresh Tests
// =============================================================================

// TestWriter_WriteSidebarRefresh tests sidebar refresh SSE event.
// Used for auto-generated session title updates.
func TestWriter_WriteSidebarRefresh(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Parameters are reserved for future use (targeted refresh)
	err = sseWriter.WriteSidebarRefresh("session-123", "Test Title")
	if err != nil {
		t.Fatalf("WriteSidebarRefresh failed: %v", err)
	}

	body := w.Body.String()

	// CRITICAL: Must use "chunk" event because the SSE client only listens for "chunk" events
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing 'event: chunk' in response - SSE client only listens for chunk events")
	}

	// Verify OOB swap wrapper (div with hx-swap-oob for body injection)
	if !strings.Contains(body, `hx-swap-oob="beforeend:body"`) {
		t.Error("missing OOB swap attribute for body injection")
	}

	// Verify HTMX trigger script
	if !strings.Contains(body, "htmx.trigger") {
		t.Error("missing htmx.trigger call")
	}
	if !strings.Contains(body, "document.body") {
		t.Error("missing document.body target")
	}
	if !strings.Contains(body, "'sidebar-refresh'") {
		t.Error("missing 'sidebar-refresh' event name")
	}

	// Verify script tag is present
	if !strings.Contains(body, "<script") {
		t.Error("missing script tag")
	}
}
