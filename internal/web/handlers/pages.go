package handlers

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/web/component"
	"github.com/koopa0/koopa-cli/internal/web/page"
)

// PagesDeps contains dependencies for the Pages handler.
type PagesDeps struct {
	Logger   *slog.Logger
	Sessions *Sessions
}

// Pages handles page rendering requests.
type Pages struct {
	logger   *slog.Logger
	sessions *Sessions
}

// NewPages creates a new Pages handler.
func NewPages(deps PagesDeps) *Pages {
	return &Pages{
		logger:   deps.Logger,
		sessions: deps.Sessions,
	}
}

// Chat renders the main chat page.
func (h *Pages) Chat(w http.ResponseWriter, r *http.Request) {
	// Check if a specific session is requested via query parameter
	requestedSessionID := r.URL.Query().Get("session")
	var sessionID uuid.UUID
	var err error

	// If no session requested, get or create one and redirect with session ID
	if requestedSessionID == "" {
		sessionID, err = h.sessions.GetOrCreate(w, r)
		if err != nil {
			h.logger.Error("session creation failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// Redirect to include session ID in URL (hypermedia principle: URL contains full state)
		// This ensures bookmarkability and proper history navigation
		http.Redirect(w, r, "/genui?session="+sessionID.String(), http.StatusSeeOther)
		return
	}

	// Use requested session if valid
	sessionID, err = uuid.Parse(requestedSessionID)
	if err != nil {
		h.logger.Warn("invalid session ID in query", "sessionID", requestedSessionID)
		// Fall back to get or create
		sessionID, err = h.sessions.GetOrCreate(w, r)
		if err != nil {
			h.logger.Error("session creation failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	csrfToken := h.sessions.NewCSRFToken(sessionID)

	// Load all sessions for sidebar
	sessions, err := h.sessions.Store().ListSessions(r.Context(), 100, 0)
	if err != nil {
		h.logger.Error("failed to load sessions", "error", err)
		// Don't fail the page, just render without sessions
		sessions = nil
	}

	// Convert to component.SessionItem
	sessionItems := make([]component.SessionItem, len(sessions))
	for i, sess := range sessions {
		sessionItems[i] = component.SessionItem{
			ID:        sess.ID,
			Title:     sess.Title,
			UpdatedAt: sess.UpdatedAt,
		}
	}

	props := page.ChatPageProps{
		SessionID: sessionID.String(),
		CSRFToken: csrfToken,
		Sessions:  sessionItems,
	}

	if err := page.Chat(props).Render(r.Context(), w); err != nil {
		h.logger.Error("failed to render chat page", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
