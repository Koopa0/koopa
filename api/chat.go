package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/firebase/genkit/go/genkit"

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

	// Handle streaming error
	if streamErr != nil {
		h.logger.Error("stream failed", "error", streamErr, "sessionId", input.SessionID)
		h.writeSSEError(w, flusher, "STREAM_ERROR", streamErr.Error())
		return
	}

	// Handle FlowError (structured error from agent)
	if finalOutput.Error != nil {
		h.logger.Error("flow error",
			"code", finalOutput.Error.Code,
			"message", finalOutput.Error.Message,
			"sessionId", input.SessionID)
		h.writeSSEError(w, flusher, finalOutput.Error.Code, finalOutput.Error.Message)
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
	data, _ := json.Marshal(SSEChunkData{Text: text})
	fmt.Fprintf(w, "event: chunk\ndata: %s\n\n", data)
	flusher.Flush()
}

// writeSSEDone writes a done event to the SSE stream.
func (h *ChatHandler) writeSSEDone(w http.ResponseWriter, flusher http.Flusher, response, sessionID string) {
	data, _ := json.Marshal(SSEDoneData{Response: response, SessionID: sessionID})
	fmt.Fprintf(w, "event: done\ndata: %s\n\n", data)
	flusher.Flush()
}

// writeSSEError writes an error event to the SSE stream.
func (h *ChatHandler) writeSSEError(w http.ResponseWriter, flusher http.Flusher, code, message string) {
	data, _ := json.Marshal(SSEErrorData{Code: code, Message: message})
	fmt.Fprintf(w, "event: error\ndata: %s\n\n", data)
	flusher.Flush()
}
