package handlers

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/web/component"
	"github.com/koopa0/koopa-cli/internal/web/page"
)

// ModeDeps contains dependencies for the Mode handler.
type ModeDeps struct {
	Logger   *slog.Logger // Per golang-master: Add logger for testability
	Sessions *Sessions
}

// Mode handles canvas/chat mode toggle operations.
type Mode struct {
	logger   *slog.Logger
	sessions *Sessions
}

// NewMode creates a Mode handler with the given dependencies.
func NewMode(deps ModeDeps) *Mode {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Mode{
		logger:   logger,
		sessions: deps.Sessions,
	}
}

// Toggle handles POST /genui/mode - toggles between chat and canvas mode.
// Accepts mode=chat or mode=canvas as query param or form value.
// Returns updated page content for HTMX swap.
// Progressive enhancement: redirects non-HTMX requests to full page.
// Security: CSRF validation required for state-changing operations.
func (m *Mode) Toggle(w http.ResponseWriter, r *http.Request) {
	// Parse form to access CSRF token
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	// CSRF validation for HTMX requests (form fallback uses session cookie)
	if IsHTMX(r) {
		sessionID, err := m.sessions.ID(r)
		if err == nil {
			// Only validate CSRF if session exists
			csrfToken := r.FormValue("csrf_token")
			if csrfToken == "" {
				csrfToken = r.URL.Query().Get("csrf_token")
			}
			if err := m.sessions.CheckCSRF(sessionID, csrfToken); err != nil {
				http.Error(w, "CSRF validation failed", http.StatusForbidden)
				return
			}
		}
	}

	// Get mode from query param (HTMX) or form value (fallback)
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = r.FormValue("mode")
	}

	// Validate mode
	canvasMode := mode == "canvas"

	// Get session ID (required for database storage)
	sessionID, err := m.sessions.ID(r)
	if err != nil {
		// No session - get or create one
		sessionID, err = m.sessions.GetOrCreate(w, r)
		if err != nil {
			http.Error(w, "Failed to get session", http.StatusInternalServerError)
			return
		}
	}

	if updateErr := m.sessions.Store().UpdateCanvasMode(r.Context(), sessionID, canvasMode); updateErr != nil {
		m.logger.Error("failed to update canvas mode", "error", updateErr, "session_id", sessionID)
		http.Error(w, "failed to update canvas mode", http.StatusInternalServerError)
		return
	}

	// Progressive enhancement: redirect non-HTMX requests
	if !IsHTMX(r) {
		http.Redirect(w, r, "/genui", http.StatusSeeOther)
		return
	}

	// Set HX-Trigger for client-side event handling
	w.Header().Set("HX-Trigger", "mode-changed")

	// Get sessions for sidebar (only sessions with messages or titles)
	// FIXED: Use ListSessionsWithMessages instead of ListSessions to avoid showing empty sessions
	sessions, err := m.sessions.Store().ListSessionsWithMessages(r.Context(), 100, 0)
	if err != nil {
		http.Error(w, "Failed to load sessions", http.StatusInternalServerError)
		return
	}

	// Convert to component.Session
	sidebarSessions := sessionsToComponent(sessions, sessionID)

	// Get messages for current session (use "main" branch)
	msgs, err := m.sessions.Store().GetMessagesByBranch(r.Context(), sessionID, "main", 100, 0)
	if err != nil {
		// Session might be new with no messages
		msgs = nil
	}

	// Convert to page.Message
	pageMessages := messagesToPage(msgs)

	// Generate CSRF token for form submissions in the new page content
	csrfToken := m.sessions.NewCSRFToken(sessionID)

	// Render ChatContent (the inner content without layout)
	w.Header().Set("Content-Type", "text/html")
	err = page.ChatContent(page.ChatContentProps{
		SessionID:  sessionID.String(),
		Sessions:   sidebarSessions,
		Messages:   pageMessages,
		CanvasMode: canvasMode,
		CSRFToken:  csrfToken,
	}).Render(r.Context(), w)
	if err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
		return
	}
}

// CanvasToggle handles POST /genui/canvas-toggle - toggles canvas mode.
//
// Behavior:
// - Toggle ON: Button updates, panel stays hidden (opens when AI replies)
// - Toggle OFF: Button updates + OOB script hides panel immediately
func (m *Mode) CanvasToggle(w http.ResponseWriter, r *http.Request) {
	// Parse form to access CSRF token
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	// Get session ID (required for database operation)
	sessionID, err := m.sessions.ID(r)
	if err != nil {
		m.logger.Warn("session required for canvas toggle", "error", err)
		http.Error(w, "session required", http.StatusBadRequest)
		return
	}

	// CSRF validation for HTMX requests
	if IsHTMX(r) {
		csrfToken := r.FormValue("csrf_token")
		if csrfToken == "" {
			csrfToken = r.URL.Query().Get("csrf_token")
		}
		if csrfErr := m.sessions.CheckCSRF(sessionID, csrfToken); csrfErr != nil {
			m.logger.Warn("CSRF validation failed", "error", csrfErr)
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
			return
		}
	}

	// Get current state from DATABASE (not cookie)
	sess, err := m.sessions.Store().GetSession(r.Context(), sessionID)
	if err != nil {
		// Per golang-master: Use correct HTTP status codes
		if errors.Is(err, session.ErrSessionNotFound) {
			m.logger.Warn("session not found", "session_id", sessionID)
			http.Error(w, "session not found", http.StatusNotFound)
		} else {
			m.logger.Error("failed to get session", "error", err, "session_id", sessionID)
			http.Error(w, "failed to load session", http.StatusInternalServerError)
		}
		return
	}

	// Toggle canvas mode
	newCanvasMode := !sess.CanvasMode

	// Update DATABASE (not cookie)
	if err := m.sessions.Store().UpdateCanvasMode(r.Context(), sessionID, newCanvasMode); err != nil {
		m.logger.Error("failed to update canvas mode", "error", err, "session_id", sessionID)
		http.Error(w, "failed to update canvas mode", http.StatusInternalServerError)
		return
	}

	m.logger.Debug("toggled canvas mode", "session_id", sessionID, "new_canvas_mode", newCanvasMode)

	// Progressive enhancement: redirect non-HTMX requests
	if !IsHTMX(r) {
		http.Redirect(w, r, "/genui", http.StatusSeeOther)
		return
	}

	// Generate new CSRF token for the button
	csrfToken := m.sessions.NewCSRFToken(sessionID)

	// Response: Button update + OOB hide script if disabling
	w.Header().Set("Content-Type", "text/html")

	// 1. Button update (primary swap)
	if err := component.CanvasToggle(sessionID.String(), csrfToken, newCanvasMode).Render(r.Context(), w); err != nil {
		m.logger.Error("failed to render button", "error", err)
		http.Error(w, "failed to render button", http.StatusInternalServerError)
		return
	}

	// 2. v4.1 FIX (per architecture-master): Hide panel when disabling canvas
	// Panel opens via SSE when AI responds, but must HIDE immediately when user toggles OFF
	if !newCanvasMode {
		_, _ = w.Write([]byte(canvasHideScript))
	}
}

// canvasHideScript - OOB script to hide panel when canvas disabled
const canvasHideScript = `<script hx-swap-oob="beforeend:body">
(function() {
    var panel = document.getElementById('artifact-panel');
    var main = document.getElementById('main-content');
    if (panel) {
        panel.classList.remove('xl:translate-x-0');
        panel.classList.add('xl:translate-x-full');
        panel.setAttribute('aria-hidden', 'true');
    }
    if (main) main.classList.remove('xl:pr-96');
    document.currentScript?.remove();
})();
</script>`

// RegisterRoutes registers mode HTTP routes on the given mux.
func (m *Mode) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /genui/mode", m.Toggle)
	mux.HandleFunc("POST /genui/canvas-toggle", m.CanvasToggle)
}
