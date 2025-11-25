package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/session"
)

// SessionHandler handles session-related HTTP endpoints.
type SessionHandler struct {
	store *session.Store
}

// NewSessionHandler creates a new session handler.
func NewSessionHandler(store *session.Store) *SessionHandler {
	return &SessionHandler{store: store}
}

// RegisterRoutes registers session routes on the given mux.
func (h *SessionHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/sessions", h.list)
	mux.HandleFunc("POST /api/sessions", h.create)
}

// list returns all sessions.
func (h *SessionHandler) list(w http.ResponseWriter, r *http.Request) {
	sessions, err := h.store.ListSessions(r.Context(), 100, 0)
	if err != nil {
		slog.Error("failed to list sessions", "error", err)
		http.Error(w, "failed to list sessions", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"sessions": sessions,
		"total":    len(sessions),
	}
	writeJSON(w, http.StatusOK, resp)
}

// CreateSessionRequest is the request body for creating a session.
type CreateSessionRequest struct {
	Title        string `json:"title"`
	ModelName    string `json:"model_name"`
	SystemPrompt string `json:"system_prompt"`
}

// create creates a new session.
func (h *SessionHandler) create(w http.ResponseWriter, r *http.Request) {
	var req CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" {
		req.Title = "New Session"
	}
	if req.ModelName == "" {
		req.ModelName = chat.DefaultModel
	}
	if req.SystemPrompt == "" {
		req.SystemPrompt = "You are a helpful assistant."
	}

	sess, err := h.store.CreateSession(r.Context(), req.Title, req.ModelName, req.SystemPrompt)
	if err != nil {
		slog.Error("failed to create session", "error", err)
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, sess)
}
