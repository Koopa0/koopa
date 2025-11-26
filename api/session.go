package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/log"
	"github.com/koopa0/koopa-cli/internal/session"
)

// Session validation constants.
const (
	MaxTitleLength        = 100
	MaxModelNameLength    = 100
	MaxSystemPromptLength = 10000
	DefaultListLimit      = 100
	MaxListLimit          = 1000
	MaxListOffset         = 100000 // Reasonable upper bound for pagination offset
)

// SessionHandler handles session-related HTTP endpoints.
type SessionHandler struct {
	store  *session.Store
	logger log.Logger
}

// NewSessionHandler creates a new session handler.
func NewSessionHandler(store *session.Store, logger log.Logger) *SessionHandler {
	return &SessionHandler{store: store, logger: logger}
}

// RegisterRoutes registers session routes on the given mux.
func (h *SessionHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/sessions", h.list)
	mux.HandleFunc("POST /api/sessions", h.create)
}

// list returns all sessions with pagination support.
// Query parameters:
//   - limit: Maximum number of sessions to return (default: 100, max: 1000)
//   - offset: Number of sessions to skip (default: 0)
func (h *SessionHandler) list(w http.ResponseWriter, r *http.Request) {
	// Check for nil store
	if h.store == nil {
		h.logger.Error("session store is nil")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Parse pagination parameters (bounded to int32-safe range by parseIntParam)
	limit := parseIntParam(r, "limit", DefaultListLimit, 1, MaxListLimit)
	offset := parseIntParam(r, "offset", 0, 0, MaxListOffset)

	// #nosec G115 -- limit and offset are bounded by MaxListLimit (1000) and MaxListOffset (100000)
	sessions, err := h.store.ListSessions(r.Context(), int32(limit), int32(offset))
	if err != nil {
		h.logger.Error("failed to list sessions", "error", err)
		http.Error(w, "failed to list sessions", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"sessions": sessions,
		"total":    len(sessions),
		"limit":    limit,
		"offset":   offset,
	}
	writeJSON(w, http.StatusOK, resp)
}

// parseIntParam parses an integer query parameter with bounds checking.
func parseIntParam(r *http.Request, name string, defaultVal, min, max int) int {
	str := r.URL.Query().Get(name)
	if str == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(str)
	if err != nil {
		return defaultVal
	}
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}

// CreateSessionRequest is the request body for creating a session.
type CreateSessionRequest struct {
	Title        string `json:"title"`
	ModelName    string `json:"model_name"`
	SystemPrompt string `json:"system_prompt"`
}

// create creates a new session.
func (h *SessionHandler) create(w http.ResponseWriter, r *http.Request) {
	// Check for nil store
	if h.store == nil {
		h.logger.Error("session store is nil")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	var req CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input lengths
	if len(req.Title) > MaxTitleLength {
		http.Error(w, "title too long (max 100 characters)", http.StatusBadRequest)
		return
	}
	if len(req.ModelName) > MaxModelNameLength {
		http.Error(w, "model_name too long (max 100 characters)", http.StatusBadRequest)
		return
	}
	if len(req.SystemPrompt) > MaxSystemPromptLength {
		http.Error(w, "system_prompt too long (max 10000 characters)", http.StatusBadRequest)
		return
	}

	// Apply defaults
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
		h.logger.Error("failed to create session", "error", err)
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, sess)
}
