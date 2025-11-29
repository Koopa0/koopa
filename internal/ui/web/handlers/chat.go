// Package handlers provides HTTP handlers for the GenUI web interface.
package handlers

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/ui/web/component"
	"github.com/koopa0/koopa-cli/internal/ui/web/sse"
)

// SSETimeout is the maximum duration for an SSE streaming connection.
// This prevents zombie goroutines from accumulating if clients disconnect
// without properly closing the connection.
const SSETimeout = 5 * time.Minute

// Chat handles chat-related HTTP requests.
// If flow is nil, the handler operates in simulation mode (returns canned responses).
// This allows development and testing without full Genkit initialization.
type Chat struct {
	logger *slog.Logger
	flow   *chat.Flow // Optional: nil enables simulation mode
}

// NewChat creates a new Chat handler.
// logger is required (panics if nil).
// flow is optional - if nil, simulation mode is used.
func NewChat(logger *slog.Logger, flow *chat.Flow) *Chat {
	if logger == nil {
		panic("NewChat: logger is required")
	}
	return &Chat{logger: logger, flow: flow}
}

// Send handles POST /genui/chat/send (HTMX form submission).
// It renders the user message and an assistant shell with SSE connection.
func (h *Chat) Send(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.logger.Error("failed to parse form", "error", err)
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	content := strings.TrimSpace(r.FormValue("content"))
	if content == "" {
		http.Error(w, "content is required", http.StatusBadRequest)
		return
	}

	sessionID := r.FormValue("sessionId")
	if sessionID == "" {
		sessionID = "default"
	}

	msgID := generateMessageID()

	// 1. Render user message
	userMsg := component.MessageBubble(component.MessageProps{
		ID:        "user-" + msgID,
		Content:   content,
		Sender:    "user",
		Timestamp: time.Now(),
	})
	if err := userMsg.Render(r.Context(), w); err != nil {
		h.logger.Error("failed to render user message", "error", err)
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}

	// 2. Render assistant message shell with scoped SSE connection
	assistantShell := component.MessageShell(component.MessageShellProps{
		ID:        "assistant-" + msgID,
		MsgID:     msgID,
		SessionID: sessionID,
		Query:     content,
	})
	if err := assistantShell.Render(r.Context(), w); err != nil {
		h.logger.Error("failed to render assistant shell", "error", err)
		return
	}
}

// Stream handles GET /genui/stream?msgId=X&sessionId=Y&query=Z (SSE endpoint).
// Each assistant message creates its own SSE connection.
func (h *Chat) Stream(w http.ResponseWriter, r *http.Request) {
	msgID := r.URL.Query().Get("msgId")
	sessionID := r.URL.Query().Get("sessionId")
	query := r.URL.Query().Get("query")

	if msgID == "" || sessionID == "" || query == "" {
		http.Error(w, "missing parameters", http.StatusBadRequest)
		return
	}

	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		h.logger.Error("SSE not supported", "error", err)
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// Apply timeout to prevent zombie connections
	ctx, cancel := context.WithTimeout(r.Context(), SSETimeout)
	defer cancel()

	// Use real Flow if available, otherwise simulate
	if h.flow != nil {
		h.streamWithFlow(ctx, sseWriter, msgID, sessionID, query)
	} else {
		h.simulateStreaming(ctx, sseWriter, msgID, query)
	}
}

// streamWithFlow uses the real chat.Flow to generate AI responses.
// It streams chunks as they arrive and sends the final message when complete.
func (h *Chat) streamWithFlow(ctx context.Context, w *sse.Writer, msgID, sessionID, query string) {
	input := chat.Input{
		Query:     query,
		SessionID: sessionID,
	}

	var (
		fullContent strings.Builder
		finalOutput chat.Output
		streamErr   error
	)

	// Iterate over streaming Flow results using Go 1.23 range-over-func
	for streamValue, err := range h.flow.Stream(ctx, input) {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			h.logContextDone(ctx, msgID)
			return
		default:
		}

		if err != nil {
			streamErr = err
			break
		}

		if streamValue.Done {
			finalOutput = streamValue.Output
			break
		}

		// Stream partial text chunks
		if streamValue.Stream.Text != "" {
			// Escape each chunk once as it arrives
			fullContent.WriteString(html.EscapeString(streamValue.Stream.Text))
			h.logger.Debug("streaming chunk",
				"msgID", msgID,
				"chunkLen", len(streamValue.Stream.Text),
				"totalLen", fullContent.Len())
			// Send accumulated HTML (already escaped)
			if err := w.WriteChunkRaw(ctx, msgID, fullContent.String()); err != nil {
				h.logger.Error("failed to write chunk", "error", err)
				return
			}
		}
	}

	// Handle errors
	if streamErr != nil {
		h.logger.Error("flow execution failed", "error", streamErr, "sessionId", sessionID)

		// Determine error code based on sentinel error type
		code := "flow_error"
		message := "Failed to generate response. Please try again."

		switch {
		case errors.Is(streamErr, agent.ErrInvalidSession):
			code = "invalid_session"
			message = "Invalid session. Please refresh the page."
		case errors.Is(streamErr, agent.ErrExecutionFailed):
			code = "execution_failed"
			message = streamErr.Error()
		case errors.Is(streamErr, context.DeadlineExceeded):
			code = "timeout"
			message = "Request timed out. Please try again."
		}

		// Attempt to send error to client
		if writeErr := w.WriteError(code, message); writeErr != nil {
			h.logger.Debug("failed to write error event (client may have disconnected)",
				"error", writeErr)
		}
		return
	}

	// Send final complete message with OOB swap
	finalMsg := component.MessageBubble(component.MessageProps{
		ID:          msgID, // Must match MessageShell.MsgID for OOB replacement
		Content:     finalOutput.Response,
		Sender:      "assistant",
		Timestamp:   time.Now(),
		IsStreaming: false,
		OOBSwap:     true, // Triggers hx-swap-oob in template
	})
	if err := w.WriteDone(ctx, finalMsg); err != nil {
		h.logger.Error("failed to send done", "error", err)
	}
}

// simulateStreaming is a placeholder for testing without real Flow.
// Used when flow is nil (simulation mode).
func (h *Chat) simulateStreaming(ctx context.Context, w *sse.Writer, msgID, query string) {
	response := fmt.Sprintf("I received your message: %q. This is a simulated response that will be replaced with actual AI streaming.", query)
	words := strings.Fields(response)

	var fullContent strings.Builder
	for i, word := range words {
		select {
		case <-ctx.Done():
			h.logContextDone(ctx, msgID)
			return
		default:
		}

		if i > 0 {
			fullContent.WriteString(" ")
		}
		fullContent.WriteString(word)

		if err := w.WriteChunk(ctx, msgID, fullContent.String()); err != nil {
			h.logger.Error("failed to send chunk", "error", err)
			return
		}

		// Simulate typing delay
		time.Sleep(50 * time.Millisecond)
	}

	// Send final complete message with OOB swap
	finalMsg := component.MessageBubble(component.MessageProps{
		ID:          msgID, // Must match MessageShell.MsgID for OOB replacement
		Content:     fullContent.String(),
		Sender:      "assistant",
		Timestamp:   time.Now(),
		IsStreaming: false,
		OOBSwap:     true, // Triggers hx-swap-oob in template
	})
	if err := w.WriteDone(ctx, finalMsg); err != nil {
		h.logger.Error("failed to send done", "error", err)
	}
}

func generateMessageID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// logContextDone logs the appropriate message based on context cancellation reason.
func (h *Chat) logContextDone(ctx context.Context, msgID string) {
	if ctx.Err() == context.DeadlineExceeded {
		h.logger.Warn("SSE connection timeout", "msgId", msgID, "timeout", SSETimeout)
	} else {
		h.logger.Info("client disconnected", "msgId", msgID)
	}
}
