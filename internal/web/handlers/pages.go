package handlers

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/web/component"
	"github.com/koopa0/koopa-cli/internal/web/page"
)

// Pagination limits for the chat page.
const (
	// DefaultMessageHistoryLimit is the maximum number of messages to load.
	DefaultMessageHistoryLimit = 50
	// DefaultSidebarSessionLimit is the maximum number of sessions shown in sidebar.
	DefaultSidebarSessionLimit = 20
)

// PagesConfig contains configuration for the Pages handler.
type PagesConfig struct {
	Logger   *slog.Logger
	Sessions *Sessions
}

// Pages handles page rendering requests.
type Pages struct {
	logger   *slog.Logger
	sessions *Sessions
}

// NewPages creates a new Pages handler.
// logger is required (panics if nil).
func NewPages(cfg PagesConfig) *Pages {
	if cfg.Logger == nil {
		panic("NewPages: logger is required")
	}
	return &Pages{
		logger:   cfg.Logger,
		sessions: cfg.Sessions,
	}
}

// Chat renders the main chat page with message history.
// Supports lazy session creation (pre-session state for fresh visitors).
// Session ID is retrieved from cookie if present; if not, page renders in pre-session state.
//
// Query Parameters:
// - session_id: Switch to an existing session (used by sidebar session links)
// - new: Create a new empty session (used by "New Chat" button)
func (h *Pages) Chat(w http.ResponseWriter, r *http.Request) {
	// Prevent caching to ensure fresh data on session switch
	// Per HTMX Master: hx-boost may cache responses, causing stale message history
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// Try to get existing session, don't create one
	// Fresh visitors will see pre-session state (no cookie, no session ID)
	sessionID, err := h.sessions.ID(r)
	hasSession := err == nil

	// Handle "New Chat" button: ?new=true creates a fresh session
	// This allows starting a new conversation without message history
	if r.URL.Query().Get("new") == "true" {
		newSession, createErr := h.sessions.Store().CreateSession(r.Context(), "", "", "")
		if createErr != nil {
			h.logger.Error("failed to create new session", "error", createErr)
			// Fall through to use existing session if any
		} else {
			sessionID = newSession.ID
			hasSession = true
			h.sessions.SetSessionCookie(w, sessionID)
			h.logger.Debug("created new session via New Chat button", "sessionID", sessionID)
		}
	} else if sessionIDStr := r.URL.Query().Get("session_id"); sessionIDStr != "" {
		// Handle session switching via query parameter
		// This allows users to switch sessions via sidebar links
		// NOTE: Removed "&&hasSession" check - users without cookie should also be able
		// to switch to an existing session (e.g., fresh visitor clicking sidebar link)
		if parsedID, parseErr := uuid.Parse(sessionIDStr); parseErr == nil {
			// Verify session exists in database
			if _, getErr := h.sessions.Store().GetSession(r.Context(), parsedID); getErr == nil {
				sessionID = parsedID
				hasSession = true // Update hasSession flag for subsequent data loading
				// Update cookie to reflect the switched session
				h.sessions.SetSessionCookie(w, sessionID)
			}
		}
	}

	// Initialize page props with defaults
	var (
		pageMessages      []page.Message
		componentSessions []component.Session
		canvasMode        bool
		csrfToken         string
		sessionIDStr      string
	)

	// Only load data if we have a session
	if hasSession {
		sessionIDStr = sessionID.String()

		// Load message history
		messages, msgErr := h.sessions.Store().GetMessagesByBranch(
			r.Context(), sessionID, "main", DefaultMessageHistoryLimit, 0,
		)
		if msgErr != nil {
			h.logger.Error("failed to load message history",
				"error", msgErr,
				"sessionID", sessionID,
			)
			// Don't fail the page load, just show empty chat
		} else {
			pageMessages = messagesToPage(messages)
		}

		// Get canvas mode from database
		currentSession, sessionErr := h.sessions.Store().GetSession(r.Context(), sessionID)
		if sessionErr == nil {
			canvasMode = currentSession.CanvasMode
		} else {
			h.logger.Warn("failed to get session for canvas mode, defaulting to false",
				"session_id", sessionID, "error", sessionErr)
		}

		// Generate session-bound CSRF token
		csrfToken = h.sessions.NewCSRFToken(sessionID)
	} else {
		// Pre-session state: Generate pre-session CSRF token
		// Session will be created on first message (lazy creation)
		csrfToken = h.sessions.NewPreSessionCSRFToken()
		h.logger.Debug("pre-session state: fresh visitor without session")
	}

	// Load sessions for sidebar (always show, even in pre-session state)
	allSessions, err := h.sessions.Store().ListSessionsWithMessages(r.Context(), DefaultSidebarSessionLimit, 0)
	if err != nil {
		h.logger.Error("failed to load sessions", "error", err)
	} else {
		componentSessions = sessionsToComponent(allSessions, sessionID)
	}

	// Render chat page
	if err := page.ChatPage(page.ChatPageProps{
		SessionID:  sessionIDStr, // Empty string in pre-session state
		Sessions:   componentSessions,
		Messages:   pageMessages,
		CanvasMode: canvasMode,
		CSRFToken:  csrfToken,
	}).Render(r.Context(), w); err != nil {
		h.logger.Error("failed to render chat page", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// Note: extractTextContent is defined in chat.go and shared across handlers package.

// RegisterRoutes registers page routes.
func (h *Pages) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /genui", h.Chat)
	mux.HandleFunc("GET /genui/", h.Chat)
	mux.HandleFunc("GET /genui/chat/{sessionID}", h.Chat)
}
