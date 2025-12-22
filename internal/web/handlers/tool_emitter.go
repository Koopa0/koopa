package handlers

import (
	"html"
	"log/slog"

	"github.com/koopa0/koopa/internal/tools"
	"github.com/koopa0/koopa/internal/web/sse"
)

// SSEToolEmitter implements ToolEventEmitter using SSE writer.
// Per architecture-master: Per-request binding for tool event streaming.
// UI presentation logic handled here, not in tools layer.
//
// Usage:
//  1. Created in streamWithFlow when starting SSE stream
//  2. Stored in context via tools.ContextWithEmitter()
//  3. Retrieved by wrapped tools via tools.EmitterFromContext()
type SSEToolEmitter struct {
	writer    *sse.Writer
	messageID string // For message-scoped indicator IDs
}

// NewSSEToolEmitter creates a new tool event emitter bound to an SSE writer.
// messageID is used for targeting the correct indicator div (per htmx-master).
func NewSSEToolEmitter(writer *sse.Writer, messageID string) *SSEToolEmitter {
	return &SSEToolEmitter{
		writer:    writer,
		messageID: messageID,
	}
}

// OnToolStart sends a tool start event via SSE.
// Looks up UI display info from tool_display.go.
// Per qa-master: Escapes messageID to prevent XSS injection.
func (e *SSEToolEmitter) OnToolStart(name string) {
	display := getToolDisplay(name)
	// Per qa-master: messageID and name must be escaped for XSS prevention
	err := e.writer.WriteToolStart(
		html.EscapeString(e.messageID),
		html.EscapeString(name),
		html.EscapeString(display.StartMsg),
		"", // icon parameter unused, SSE writer determines icon from toolName
	)
	if err != nil {
		// Per v4: Log errors but don't disrupt tool execution
		slog.Debug("SSE write error on tool start",
			"tool", name,
			"messageID", e.messageID,
			"error", err,
		)
	}
}

// OnToolComplete sends a tool complete event via SSE.
func (e *SSEToolEmitter) OnToolComplete(name string) {
	display := getToolDisplay(name)
	err := e.writer.WriteToolComplete(
		html.EscapeString(e.messageID),
		html.EscapeString(name),
		html.EscapeString(display.CompleteMsg),
	)
	if err != nil {
		slog.Debug("SSE write error on tool complete",
			"tool", name,
			"messageID", e.messageID,
			"error", err,
		)
	}
}

// OnToolError sends a tool error event via SSE.
func (e *SSEToolEmitter) OnToolError(name string) {
	display := getToolDisplay(name)
	err := e.writer.WriteToolError(
		html.EscapeString(e.messageID),
		html.EscapeString(name),
		html.EscapeString(display.ErrorMsg),
	)
	if err != nil {
		slog.Debug("SSE write error on tool error",
			"tool", name,
			"messageID", e.messageID,
			"error", err,
		)
	}
}

// Compile-time interface verification
var _ tools.ToolEventEmitter = (*SSEToolEmitter)(nil)
