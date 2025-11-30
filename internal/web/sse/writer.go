// Package sse provides Server-Sent Events utilities for streaming responses.
package sse

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
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
		return nil, fmt.Errorf("response writer does not support flusher interface")
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

// WriteEvent sends a named event with raw HTML content.
// HTMX SSE extension expects raw HTML in the data field, not JSON.
func (w *Writer) WriteEvent(ctx context.Context, event string, comp templ.Component) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled: %w", ctx.Err())
	default:
	}

	var buf bytes.Buffer
	if err := comp.Render(ctx, &buf); err != nil {
		return fmt.Errorf("render component: %w", err)
	}

	return w.writeSSEData(event, buf.String())
}

// WriteChunk sends a streaming text chunk with OOB swap.
// The text is HTML-escaped to prevent XSS attacks.
// HTMX SSE extension expects raw HTML in the data field, not JSON.
func (w *Writer) WriteChunk(ctx context.Context, msgID, text string) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled: %w", ctx.Err())
	default:
	}

	// Escape text to prevent XSS - this bypasses templ so we must escape manually
	escapedText := html.EscapeString(text)

	// OOB swap to update content only - send raw HTML, not JSON
	htmlContent := fmt.Sprintf(`<div id="msg-content-%s" hx-swap-oob="innerHTML">%s</div>`, msgID, escapedText)
	return w.writeSSEData("chunk", htmlContent)
}

// WriteChunkRaw sends already-escaped HTML content as an OOB swap.
// Use this when accumulating content where escaping happens once in the callback
// to avoid double-escaping. The caller is responsible for escaping the content.
// HTMX SSE extension expects raw HTML in the data field, not JSON.
func (w *Writer) WriteChunkRaw(ctx context.Context, msgID, htmlContent string) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled: %w", ctx.Err())
	default:
	}

	// No html.EscapeString() - content already escaped by caller
	// Send raw HTML, not JSON
	oobHTML := fmt.Sprintf(`<div id="msg-content-%s" hx-swap-oob="innerHTML">%s</div>`, msgID, htmlContent)
	return w.writeSSEData("chunk", oobHTML)
}

// WriteDone sends the final message event.
func (w *Writer) WriteDone(ctx context.Context, comp templ.Component) error {
	return w.WriteEvent(ctx, "done", comp)
}

// WriteError sends an error event.
func (w *Writer) WriteError(code, message string) error {
	payload := map[string]string{"code": code, "message": message}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	if _, err := fmt.Fprintf(w.w, "event: error\ndata: %s\n\n", data); err != nil {
		return fmt.Errorf("write error: %w", err)
	}
	w.flusher.Flush()
	return nil
}
