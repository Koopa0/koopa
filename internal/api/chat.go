package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/firebase/genkit/go/genkit"

	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/log"
)

// Chat handles chat-related HTTP endpoints via Genkit Flow.
//
// Endpoints:
//   - POST /api/chat        - Synchronous chat (JSON request/response)
//   - POST /api/chat/stream - Streaming chat (SSE - Server-Sent Events)
//
// Design: Uses genkit.Handler() for synchronous endpoint, and custom SSE
// handler for streaming. Both go through the same Flow for consistency.
type Chat struct {
	flow   *chat.Flow
	logger log.Logger
}

// NewChat creates a new chat handler with the given Flow.
// The Flow should be obtained from chat.DefineFlow().
func NewChat(flow *chat.Flow, logger log.Logger) *Chat {
	return &Chat{flow: flow, logger: logger}
}

// RegisterRoutes registers chat routes on the given mux.
// If flow is nil, routes are not registered and requests will return 404.
func (h *Chat) RegisterRoutes(mux *http.ServeMux) {
	if h.flow == nil {
		h.logger.Warn("chat flow not configured, skipping route registration")
		return
	}

	// Synchronous endpoint using Genkit's built-in handler
	mux.Handle("POST /api/chat", genkit.Handler(h.flow))

	// SSE streaming endpoint
	mux.HandleFunc("POST /api/chat/stream", h.Stream)
}

// SSE event types for chat streaming.
const (
	EventChunk = "chunk" // Partial response text
	EventDone  = "done"  // Stream completed successfully
	EventError = "error" // Error occurred during streaming
)

// ChunkPayload is the SSE data payload for streaming text chunks.
type ChunkPayload struct {
	Text string `json:"text"`
}

// DonePayload is the SSE data payload when streaming completes successfully.
type DonePayload struct {
	Response  string `json:"response"`
	SessionID string `json:"sessionId"`
}

// ErrorPayload is the SSE data payload when an error occurs.
type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Stream handles SSE streaming chat requests.
// It streams partial responses as they become available from the LLM.
func (h *Chat) Stream(w http.ResponseWriter, r *http.Request) {
	// 1. Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// 2. Verify Flusher support
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// 3. Parse input
	var input chat.Input
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // Limit request size to 1MB
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		_ = writeEvent(w, flusher, EventError, ErrorPayload{
			Code:    "INVALID_REQUEST",
			Message: "Invalid request body",
		})
		return
	}

	if input.SessionID == "" {
		_ = writeEvent(w, flusher, EventError, ErrorPayload{Code: "MISSING_SESSION_ID", Message: "sessionId is required"})
		return
	}
	if input.Query == "" {
		_ = writeEvent(w, flusher, EventError, ErrorPayload{Code: "MISSING_QUERY", Message: "query is required"})
		return
	}

	// 4. Defensive nil check before streaming (normally routes aren't registered if flow is nil)
	if h.flow == nil {
		_ = writeEvent(w, flusher, EventError, ErrorPayload{Code: "FLOW_NOT_CONFIGURED", Message: "chat flow not configured"})
		return
	}

	ctx := r.Context()
	h.logger.Debug("SSE stream started", "sessionId", input.SessionID)

	var (
		finalOutput chat.Output
		streamErr   error
		hasChunks   bool
	)

	for streamValue, err := range h.flow.Stream(ctx, input) {
		select {
		case <-ctx.Done():
			h.logger.Info("client disconnected", "sessionId", input.SessionID)
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

		if streamValue.Stream.Text != "" {
			hasChunks = true
			if err := writeEvent(w, flusher, EventChunk, ChunkPayload{
				Text: streamValue.Stream.Text,
			}); err != nil {
				h.logger.Error("failed to write chunk", "err", err)
				return // Write failure usually means connection closed
			}
		}
	}

	// 4. Handle errors and finalize
	if streamErr != nil {
		h.handleStreamError(w, flusher, streamErr)
		return
	}

	// Send done event
	_ = writeEvent(w, flusher, EventDone, DonePayload{
		Response:  finalOutput.Response,
		SessionID: finalOutput.SessionID,
	})

	h.logger.Info("SSE stream completed", "sessionId", input.SessionID, "chunks", hasChunks)
}

// handleStreamError maps agent errors to SSE error events.
func (*Chat) handleStreamError(w io.Writer, f http.Flusher, err error) {
	code := "STREAM_ERROR"

	switch {
	case errors.Is(err, agent.ErrInvalidSession):
		code = "INVALID_SESSION"
	case errors.Is(err, agent.ErrExecutionFailed):
		code = "EXECUTION_FAILED"
	case errors.Is(err, agent.ErrRateLimited):
		code = "RATE_LIMITED"
	case errors.Is(err, agent.ErrModelUnavailable):
		code = "MODEL_UNAVAILABLE"
	}

	_ = writeEvent(w, f, EventError, ErrorPayload{
		Code:    code,
		Message: err.Error(),
	})
}

// writeEvent writes a single SSE event with JSON-encoded data.
// SSE format: "event: <type>\ndata: <json>\n\n"
func writeEvent[T any](w io.Writer, flusher http.Flusher, event string, data T) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, jsonData); err != nil {
		return fmt.Errorf("write event: %w", err)
	}

	flusher.Flush()
	return nil
}
