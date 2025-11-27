package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/firebase/genkit/go/genkit"

	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/log"
)

// ChatHandler handles chat-related HTTP endpoints via Genkit Flow.
//
// Endpoints:
//   - POST /api/chat        - Synchronous chat (JSON request/response)
//   - POST /api/chat/stream - Streaming chat (SSE - Server-Sent Events)
//
// Design: Uses genkit.Handler() for synchronous endpoint, and custom SSE
// handler for streaming. Both go through the same Flow for consistency.
//
// P0 Fixes Applied:
//   - Panic recovery to prevent server crashes
//   - JSON marshal error handling
//   - Proper error handling using sentinel errors
type ChatHandler struct {
	chatFlow *chat.Flow
	logger   log.Logger
}

// NewChatHandler creates a new chat handler with the given Flow.
// The Flow should be obtained from chat.DefineFlow().
func NewChatHandler(flow *chat.Flow, logger log.Logger) *ChatHandler {
	return &ChatHandler{chatFlow: flow, logger: logger}
}

// RegisterRoutes registers chat routes on the given mux.
func (h *ChatHandler) RegisterRoutes(mux *http.ServeMux) {
	if h.chatFlow != nil {
		// Synchronous endpoint using Genkit's built-in handler
		mux.Handle("POST /api/chat", genkit.Handler(h.chatFlow))

		// SSE streaming endpoint
		mux.HandleFunc("POST /api/chat/stream", h.handleStream)
	} else if h.logger != nil {
		h.logger.Warn("ChatHandler: chatFlow is nil, chat endpoints not registered")
	}
}

// SSEEvent represents a Server-Sent Event payload.
type SSEEvent struct {
	// Event type: "chunk" for partial text, "done" for final output, "error" for errors
	Event string `json:"event"`

	// Data payload - depends on event type
	Data any `json:"data"`
}

// SSEChunkData is the data for "chunk" events.
type SSEChunkData struct {
	Text string `json:"text"`
}

// SSEDoneData is the data for "done" events.
type SSEDoneData struct {
	Response  string `json:"response"`
	SessionID string `json:"sessionId"`
}

// SSEErrorData is the data for "error" events.
type SSEErrorData struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// handleStream handles the SSE streaming endpoint.
// This provides real-time streaming output for chat responses.
//
// Request body: {"query": "...", "sessionId": "..."}
// Response: Server-Sent Events stream
//
// Event types:
//   - chunk: Partial text chunk {"text": "..."}
//   - done:  Final response {"response": "...", "sessionId": "..."}
//   - error: Error occurred {"code": "...", "message": "..."}
func (h *ChatHandler) handleStream(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			h.logger.Error("panic in SSE handler",
				"recover", rec,
				"stack", string(debug.Stack()))

			// Try to send error event if possible
			if flusher, ok := w.(http.Flusher); ok {
				h.writeSSEError(w, flusher, "INTERNAL_ERROR", "internal server error")
			}
		}
	}()

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering

	// Check if streaming is supported
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.logger.Error("streaming not supported")
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Parse request body
	var input chat.Input
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.writeSSEError(w, flusher, "INVALID_REQUEST", fmt.Sprintf("Invalid request body: %v", err))
		return
	}

	// Validate input
	if input.SessionID == "" {
		h.writeSSEError(w, flusher, "MISSING_SESSION_ID", "sessionId is required")
		return
	}
	if input.Query == "" {
		h.writeSSEError(w, flusher, "MISSING_QUERY", "query is required")
		return
	}

	ctx := r.Context()
	h.logger.Info("SSE stream started", "sessionId", input.SessionID)

	// Stream from Flow
	var finalOutput chat.Output
	var streamErr error
	hasChunks := false

	for streamValue, err := range h.chatFlow.Stream(ctx, input) {
		// Check if client disconnected
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
			// Final output received
			finalOutput = streamValue.Output
			break
		}

		// Stream partial text immediately
		if streamValue.Stream.Text != "" {
			hasChunks = true
			h.writeSSEChunk(w, flusher, streamValue.Stream.Text)
		}
	}

	if streamErr != nil {
		h.logger.Error("stream failed", "error", streamErr, "sessionId", input.SessionID)

		// Map sentinel errors to appropriate error codes
		code := "STREAM_ERROR"
		if errors.Is(streamErr, agent.ErrInvalidSession) {
			code = "INVALID_SESSION"
		} else if errors.Is(streamErr, agent.ErrExecutionFailed) {
			code = "EXECUTION_FAILED"
		} else if errors.Is(streamErr, agent.ErrRateLimited) {
			code = "RATE_LIMITED"
		} else if errors.Is(streamErr, agent.ErrModelUnavailable) {
			code = "MODEL_UNAVAILABLE"
		}

		h.writeSSEError(w, flusher, code, streamErr.Error())
		return
	}

	// Send done event with final response
	h.writeSSEDone(w, flusher, finalOutput.Response, finalOutput.SessionID)
	h.logger.Info("SSE stream completed",
		"sessionId", input.SessionID,
		"hasChunks", hasChunks,
		"responseLen", len(finalOutput.Response))
}

// writeSSEChunk writes a chunk event to the SSE stream.
func (h *ChatHandler) writeSSEChunk(w http.ResponseWriter, flusher http.Flusher, text string) {
	data, err := json.Marshal(SSEChunkData{Text: text})
	if err != nil {
		h.logger.Error("failed to marshal SSE chunk", "error", err)
		// Send fallback error event
		h.writeSSEErrorRaw(w, flusher, "MARSHAL_ERROR", "failed to encode chunk")
		return
	}
	fmt.Fprintf(w, "event: chunk\ndata: %s\n\n", data)
	flusher.Flush()
}

// writeSSEDone writes a done event to the SSE stream.
func (h *ChatHandler) writeSSEDone(w http.ResponseWriter, flusher http.Flusher, response, sessionID string) {
	data, err := json.Marshal(SSEDoneData{Response: response, SessionID: sessionID})
	if err != nil {
		h.logger.Error("failed to marshal SSE done", "error", err)
		// Send fallback error event
		h.writeSSEErrorRaw(w, flusher, "MARSHAL_ERROR", "failed to encode response")
		return
	}
	fmt.Fprintf(w, "event: done\ndata: %s\n\n", data)
	flusher.Flush()
}

// writeSSEError writes an error event to the SSE stream.
func (h *ChatHandler) writeSSEError(w http.ResponseWriter, flusher http.Flusher, code, message string) {
	data, err := json.Marshal(SSEErrorData{Code: code, Message: message})
	if err != nil {
		h.logger.Error("failed to marshal SSE error", "error", err, "code", code)
		// Use raw fallback
		h.writeSSEErrorRaw(w, flusher, code, message)
		return
	}
	fmt.Fprintf(w, "event: error\ndata: %s\n\n", data)
	flusher.Flush()
}

// writeSSEErrorRaw writes an error event using a pre-formatted string (fallback for marshal errors).
func (h *ChatHandler) writeSSEErrorRaw(w http.ResponseWriter, flusher http.Flusher, code, message string) {
	// Escape special characters for JSON safety
	escapedCode := escapeJSON(code)
	escapedMsg := escapeJSON(message)
	fmt.Fprintf(w, "event: error\ndata: {\"code\":\"%s\",\"message\":\"%s\"}\n\n", escapedCode, escapedMsg)
	flusher.Flush()
}

// escapeJSON escapes special characters for JSON string values.
func escapeJSON(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			result = append(result, '\\', '"')
		case '\\':
			result = append(result, '\\', '\\')
		case '\n':
			result = append(result, '\\', 'n')
		case '\r':
			result = append(result, '\\', 'r')
		case '\t':
			result = append(result, '\\', 't')
		default:
			if c < 0x20 {
				// Control characters - skip or escape
				result = append(result, '\\', 'u', '0', '0', hexDigit(c>>4), hexDigit(c&0xf))
			} else {
				result = append(result, c)
			}
		}
	}
	return string(result)
}

func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + n - 10
}
