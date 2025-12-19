// Package sse provides Server-Sent Events utilities for streaming responses.
package sse

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/a-h/templ"
)

// Writer wraps an http.ResponseWriter for SSE streaming.
type Writer struct {
	w       io.Writer
	flusher http.Flusher
}

// NewWriter creates a new SSE writer and sets appropriate headers.
func NewWriter(w http.ResponseWriter) (*Writer, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("ResponseWriter does not implement http.Flusher")
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering

	return &Writer{w: w, flusher: flusher}, nil
}

// writeSSEData writes data in SSE format, handling multi-line content.
// SSE spec requires each line of data to be prefixed with "data: ".
func (w *Writer) writeSSEData(event, content string) error {
	if _, err := fmt.Fprintf(w.w, "event: %s\n", event); err != nil {
		return fmt.Errorf("write event name: %w", err)
	}

	// Handle multi-line content: each line needs "data: " prefix
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if _, err := fmt.Fprintf(w.w, "data: %s\n", line); err != nil {
			return fmt.Errorf("write data line: %w", err)
		}
	}

	// Empty line terminates the event
	if _, err := w.w.Write([]byte("\n")); err != nil {
		return fmt.Errorf("write terminator: %w", err)
	}

	w.flusher.Flush()
	return nil
}

// WriteChunk sends a chunk event with a rendered templ component as OOB swap.
// This is type-safe: templ automatically escapes all content to prevent XSS.
// Use this when you have a templ.Component to render.
func (w *Writer) WriteChunk(ctx context.Context, msgID string, comp templ.Component) error {
	var buf bytes.Buffer
	if err := comp.Render(ctx, &buf); err != nil {
		return fmt.Errorf("render component: %w", err)
	}

	oobHTML := fmt.Sprintf(`<div id="msg-content-%s" hx-swap-oob="innerHTML">%s</div>`, msgID, buf.String())
	return w.writeSSEData("chunk", oobHTML)
}

// WriteChunkRaw sends already-escaped HTML content directly via SSE.
// SECURITY: Caller is responsible for escaping content to prevent XSS.
// Use this for performance in streaming loops where content is pre-escaped.
//
// SSE Architecture (per HTMX Master review):
// - Client has sse-swap="chunk" attribute which listens for "chunk" events
// - This method sends plain HTML content - no OOB wrapper needed
// - HTMX SSE extension swaps the content directly into the target element
// - msgID parameter is kept for API compatibility but not used in output
//
// Context checks are intentionally omitted - write errors propagate naturally
// if client disconnects. The handler manages context cancellation in its loop.
func (w *Writer) WriteChunkRaw(msgID, htmlContent string) error {
	// Send plain HTML content - sse-swap="chunk" on client will handle the swap
	// msgID kept for logging/debugging purposes but not included in output
	_ = msgID // Unused but kept for API compatibility and potential logging
	return w.writeSSEData("chunk", htmlContent)
}

// WriteDone sends the final message and closes the SSE connection.
// Per HTMX Master: sse-close="done" closes BEFORE processing swap content.
// Solution: Send final content as "chunk" OOB swap, then empty "done" to close.
//
// msgID: message ID for OOB swap targeting (replaces entire message div)
// comp: final message component with action buttons
func (w *Writer) WriteDone(ctx context.Context, msgID string, comp templ.Component) error {
	// 1. Render final message component
	var buf bytes.Buffer
	if err := comp.Render(ctx, &buf); err != nil {
		return fmt.Errorf("render component: %w", err)
	}

	// 2. Send as OOB swap targeting the ENTIRE message div (outerHTML)
	// This replaces the streaming component with final message + action buttons
	oobHTML := fmt.Sprintf(`<div id="message-%s" hx-swap-oob="outerHTML">%s</div>`, msgID, buf.String())
	if err := w.writeSSEData("chunk", oobHTML); err != nil {
		return fmt.Errorf("write final chunk: %w", err)
	}

	// 3. Send empty "done" event to close SSE connection
	// Client has sse-close="done" which triggers on this event
	return w.writeSSEData("done", "")
}

// WriteError sends an error event as HTML OOB swap to replace the streaming content.
// This ensures the error is visible to users (not silently ignored).
// msgID is used to target the correct message content div.
// No context needed - errors are fire-and-forget (client may already be disconnected).
func (w *Writer) WriteError(msgID, _, message string) error {
	// Build user-friendly error HTML that replaces the skeleton loader
	errorHTML := fmt.Sprintf(`<div class="flex items-center gap-2 text-red-400">
<svg class="size-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<circle cx="12" cy="12" r="10"></circle>
<line x1="12" y1="8" x2="12" y2="12"></line>
<line x1="12" y1="16" x2="12.01" y2="16"></line>
</svg>
<span class="text-sm">%s</span>
</div>`, template.HTMLEscapeString(message))

	// Send as OOB swap targeting the message content div
	oobHTML := fmt.Sprintf(`<div id="msg-content-%s" hx-swap-oob="innerHTML">%s</div>`, msgID, errorHTML)
	return w.writeSSEData("error", oobHTML)
}

// =============================================================================
// Canvas Mode Methods (Artifact Panel Support)
// =============================================================================

// WriteArtifact sends an artifact update to the Canvas panel.
// Used for displaying generated code, documents, or other rich content.
// Context is passed for component rendering cancellation.
//
// Uses OOB swap to update #artifact-content div.
// The panel visibility is controlled separately via WriteCanvasShow().
//
// CRITICAL: Must send via "chunk" event because the SSE client only listens
// for "chunk" events via sse-swap="chunk". Events sent with other names
// (like "artifact") are silently ignored by the HTMX SSE extension.
func (w *Writer) WriteArtifact(ctx context.Context, comp templ.Component) error {
	var buf bytes.Buffer
	if err := comp.Render(ctx, &buf); err != nil {
		return fmt.Errorf("render artifact component: %w", err)
	}

	// Wrap in OOB swap targeting artifact-content div
	oobHTML := fmt.Sprintf(`<div id="artifact-content" hx-swap-oob="innerHTML">%s</div>`, buf.String())
	return w.writeSSEData("chunk", oobHTML) // Must use "chunk" - see comment above
}

// WriteWithArtifact sends both a message chunk and artifact update in one event.
// This reduces network round-trips when both panels need updating.
// Context is passed for component rendering cancellation.
func (w *Writer) WriteWithArtifact(ctx context.Context, msgID, msgHTML string, artifactComp templ.Component) error {
	// Send message chunk first
	if err := w.WriteChunkRaw(msgID, msgHTML); err != nil {
		return fmt.Errorf("write chunk: %w", err)
	}

	// Send artifact update
	return w.WriteArtifact(ctx, artifactComp)
}

// ClearArtifact sends an event to clear/reset the Canvas panel.
// Used when switching modes or when artifact content is no longer relevant.
// Context is passed for component rendering cancellation.
//
// CRITICAL: Must send via "chunk" event because the SSE client only listens
// for "chunk" events via sse-swap="chunk". Events sent with other names
// (like "artifact-clear") are silently ignored by the HTMX SSE extension.
func (w *Writer) ClearArtifact(ctx context.Context, emptyStateComp templ.Component) error {
	var buf bytes.Buffer
	if err := emptyStateComp.Render(ctx, &buf); err != nil {
		return fmt.Errorf("render empty state component: %w", err)
	}

	// Wrap in OOB swap targeting artifact-content div
	oobHTML := fmt.Sprintf(`<div id="artifact-content" hx-swap-oob="innerHTML">%s</div>`, buf.String())
	return w.writeSSEData("chunk", oobHTML) // Must use "chunk" - see comment above
}

// WriteSidebarRefresh sends an HX-Trigger event to refresh the sidebar.
// Used after title is auto-generated to update the session list.
// Per HTMX Master: Use HX-Trigger header pattern via SSE instead of OOB trigger div.
// The client sidebar has hx-trigger="sidebar-refresh from:body" which catches this event.
// Note: sessionID and title parameters reserved for future use (logging, targeted refresh).
//
// CRITICAL: Must send via "chunk" event because the SSE client only listens for "chunk" events
// via sse-swap="chunk". Events sent with other names (like "sidebar") are silently ignored.
func (w *Writer) WriteSidebarRefresh(_, _ string) error {
	// Send sidebar refresh trigger via "chunk" event (the only event the SSE client listens to)
	// Uses OOB swap to inject a script that triggers the sidebar-refresh event on body
	// The sidebar has hx-trigger="sidebar-refresh from:body" which catches this event
	triggerHTML := `<div hx-swap-oob="beforeend:body"><script data-sidebar-refresh>(function(){htmx.trigger(document.body,'sidebar-refresh');document.currentScript.remove();})();</script></div>`
	return w.writeSSEData("chunk", triggerHTML)
}

// =============================================================================
// Canvas Panel Dynamic Display
// =============================================================================

// WriteCanvasShow sends an SSE event to dynamically show the Canvas panel.
// Per HTMX Master review: Uses script injection instead of invalid hx-swap-oob="className".
// The panel uses translate-x-full (hidden) → translate-x-0 (visible) animation.
// Panel should appear when AI signals an artifact, not on button click.
//
// CRITICAL: Must send via "chunk" event because the SSE client only listens for "chunk" events.
//
// Implementation: Single SSE event with self-removing script that:
// 1. Removes 'hidden' class (CSS display:none) to make panel visible
// 2. Removes xl:translate-x-full from panel (slides in)
// 3. Adds xl:translate-x-0 to panel (visible position)
// 4. Adds 'xl:flex' for proper desktop layout
// 5. Updates aria-hidden for accessibility
// 6. Adds xl:pr-96 to main content (layout shift)
func (w *Writer) WriteCanvasShow() error {
	showScript := `<div hx-swap-oob="beforeend:body"><script data-canvas-toggle>
(function() {
    var panel = document.getElementById('artifact-panel');
    var main = document.getElementById('main-content');
    if (panel) {
        panel.classList.remove('hidden', 'xl:translate-x-full');
        panel.classList.add('xl:translate-x-0', 'xl:flex');
        panel.setAttribute('aria-hidden', 'false');
    }
    if (main) {
        main.classList.add('xl:pr-96');
    }
    document.currentScript?.remove();
})();
</script></div>`
	return w.writeSSEData("chunk", showScript)
}

// WriteCanvasHide sends an SSE event to dynamically hide the Canvas panel.
// Uses script injection for class toggling (per HTMX Master review).
// Called when Canvas mode is disabled or when clearing artifact content.
//
// CRITICAL: Must send via "chunk" event because the SSE client only listens for "chunk" events.
func (w *Writer) WriteCanvasHide() error {
	hideScript := `<div hx-swap-oob="beforeend:body"><script data-canvas-toggle>
(function() {
    var panel = document.getElementById('artifact-panel');
    var main = document.getElementById('main-content');
    if (panel) {
        panel.classList.remove('xl:translate-x-0');
        panel.classList.add('xl:translate-x-full');
        panel.setAttribute('aria-hidden', 'true');
    }
    if (main) {
        main.classList.remove('xl:pr-96');
    }
    document.currentScript?.remove();
})();
</script></div>`
	return w.writeSSEData("chunk", hideScript)
}

// =============================================================================
// Tool Execution Visual Feedback
// =============================================================================

// WriteToolStart sends a tool execution start event.
// Per ui-master: Tool-specific icons for better UX.
// Per htmx-master: Message-scoped ID for concurrent tools.
//
// messageID: for targeting the correct indicator div
// toolName: tool identifier (e.g., "web_search")
// message: user-friendly message (e.g., "搜尋網路中...")
// icon: icon hint (currently unused, icon determined by toolName)
func (w *Writer) WriteToolStart(messageID, toolName, message, _ string) error {
	id := fmt.Sprintf("tool-indicator-%s", messageID)

	// Get tool-specific icon SVG
	iconSVG := getToolIcon(toolName, "running")

	// Per ui-master: animate-pulse for text, role="status" for accessibility
	//nolint:gocritic // sprintfQuotedString: HTML template, not quoted string
	indicatorHTML := fmt.Sprintf(`<div id="%s" hx-swap-oob="outerHTML" role="status" aria-live="polite" class="flex items-center gap-2 text-sm text-gray-400 py-2">%s<span class="animate-pulse">%s</span></div>`,
		id, iconSVG, template.HTMLEscapeString(message))

	return w.writeSSEData("tool-start", indicatorHTML)
}

// WriteToolComplete sends a tool execution complete event.
// Per htmx-master: Clear indicator by replacing with empty div.
//
// messageID: for targeting the correct indicator div
// toolName: tool identifier (for logging)
// message: completion message (currently unused in output)
func (w *Writer) WriteToolComplete(messageID, _, _ string) error {
	id := fmt.Sprintf("tool-indicator-%s", messageID)

	// Empty div to hide indicator (preserves element for future tool calls)
	// Per htmx-master: empty:hidden CSS class handles visual hiding
	//nolint:gocritic // sprintfQuotedString: HTML template, not quoted string
	completeHTML := fmt.Sprintf(`<div id="%s" hx-swap-oob="outerHTML" role="status" aria-live="polite"></div>`, id)

	return w.writeSSEData("tool-complete", completeHTML)
}

// WriteToolError sends a tool execution error event.
// Per ui-master: Use amber color for warnings, role="alert" for errors.
//
// messageID: for targeting the correct indicator div
// toolName: tool identifier (for icon selection)
// userMessage: user-friendly error message (not internal error details)
func (w *Writer) WriteToolError(messageID, toolName, userMessage string) error {
	id := fmt.Sprintf("tool-indicator-%s", messageID)

	// Get error icon (no animation)
	iconSVG := getToolIcon(toolName, "error")

	// Per ui-master: amber color for warnings, aria-live="assertive" for errors
	//nolint:gocritic // sprintfQuotedString: HTML template, not quoted string
	errorHTML := fmt.Sprintf(`<div id="%s" hx-swap-oob="outerHTML" role="alert" aria-live="assertive" class="flex items-center gap-2 text-sm text-amber-400 py-2">%s<span>%s</span></div>`,
		id, iconSVG, template.HTMLEscapeString(userMessage))

	return w.writeSSEData("tool-error", errorHTML)
}

// getToolIcon returns the appropriate SVG icon for a tool.
// Per ui-master: Tool-specific icons improve recognition.
func getToolIcon(toolName, status string) string {
	// Spinning animation class for running status
	spinClass := ""
	if status == "running" {
		spinClass = " animate-spin"
	}

	switch toolName {
	case "web_search":
		// Globe icon for search
		return fmt.Sprintf(`<svg class="size-4 text-indigo-400%s" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`, spinClass)

	case "web_fetch":
		// Document/page icon for fetch
		return fmt.Sprintf(`<svg class="size-4 text-indigo-400%s" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14,2 14,8 20,8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>`, spinClass)

	case "read_file", "write_file", "list_directory":
		// Folder icon for file operations
		return fmt.Sprintf(`<svg class="size-4 text-indigo-400%s" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`, spinClass)

	case "execute_command":
		// Terminal icon for commands
		return fmt.Sprintf(`<svg class="size-4 text-indigo-400%s" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4,17 10,11 4,5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`, spinClass)

	case "knowledge_search", "knowledge_store":
		// Brain/database icon for knowledge operations
		return fmt.Sprintf(`<svg class="size-4 text-indigo-400%s" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>`, spinClass)

	default:
		// Generic cog/gear icon
		return fmt.Sprintf(`<svg class="size-4 text-indigo-400%s" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>`, spinClass)
	}
}
