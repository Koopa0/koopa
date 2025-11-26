package api

import (
	"net/http"

	"github.com/firebase/genkit/go/genkit"

	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/log"
)

// ChatHandler handles chat-related HTTP endpoints via Genkit Flow.
//
// Design: Uses genkit.Handler() to automatically expose the Chat Flow as HTTP.
// This provides:
//   - Automatic JSON serialization/deserialization
//   - Input/Output schema validation
//   - Observability (tracing, logging)
//   - Consistent error handling
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
		// Use Genkit's built-in handler for Flow-to-HTTP conversion
		mux.Handle("POST /api/chat", genkit.Handler(h.chatFlow))
	} else {
		h.logger.Warn("ChatHandler: chatFlow is nil, /api/chat endpoint not registered")
	}
}
