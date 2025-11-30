// Package handlers provides HTTP handlers for the GenUI web interface.
package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/web/component"
)

// Sentinel errors for session/CSRF operations.
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionInvalid  = errors.New("session ID invalid")
	ErrCSRFRequired    = errors.New("CSRF token required")
	ErrCSRFInvalid     = errors.New("CSRF token invalid")
	ErrCSRFExpired     = errors.New("CSRF token expired")
	ErrCSRFMalformed   = errors.New("CSRF token malformed")
)

// Cookie configuration.
const (
	SessionCookieName = "sid"          // Generic name, doesn't leak tech stack
	CSRFTokenTTL      = 24 * time.Hour // Token validity period
	SessionMaxAge     = 30 * 24 * 3600 // 30 days in seconds
	CSRFClockSkew     = 5 * time.Minute
)

// Sessions handles HTTP session cookies and CSRF token operations.
// Named as plural noun (Go stdlib style: http.Cookies, not CookieManager).
// Uses composition with session.Store for database persistence.
type Sessions struct {
	store      *session.Store
	hmacSecret []byte
}

// NewSessions creates a Sessions handler with the given store and HMAC secret.
// The secret must be at least 32 bytes for HMAC-SHA256 security.
func NewSessions(store *session.Store, hmacSecret []byte) *Sessions {
	return &Sessions{
		store:      store,
		hmacSecret: hmacSecret,
	}
}

// GetOrCreate retrieves session ID from cookie or creates a new session.
// On success, sets/refreshes the session cookie and returns the session UUID.
func (s *Sessions) GetOrCreate(w http.ResponseWriter, r *http.Request) (uuid.UUID, error) {
	// Try to get existing session from cookie
	cookie, err := r.Cookie(SessionCookieName)
	if err == nil && cookie.Value != "" {
		sessionID, parseErr := uuid.Parse(cookie.Value)
		if parseErr == nil {
			// Verify session exists in database
			_, getErr := s.store.GetSession(r.Context(), sessionID)
			if getErr == nil {
				// Refresh cookie expiry
				s.setCookie(w, sessionID)
				return sessionID, nil
			}
			// Session not in DB, fall through to create new
		}
	}

	// Create new session in database
	sess, err := s.store.CreateSession(r.Context(), "", "", "")
	if err != nil {
		return uuid.Nil, fmt.Errorf("create session: %w", err)
	}

	// Set cookie with new session ID
	s.setCookie(w, sess.ID)
	return sess.ID, nil
}

// ID extracts session ID from cookie without creating new session.
// Returns ErrSessionNotFound if cookie is missing or invalid.
func (*Sessions) ID(r *http.Request) (uuid.UUID, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return uuid.Nil, ErrSessionNotFound
	}

	sessionID, err := uuid.Parse(cookie.Value)
	if err != nil {
		return uuid.Nil, ErrSessionInvalid
	}

	return sessionID, nil
}

// NewCSRFToken creates an HMAC-based token: "timestamp:signature".
// The token is bound to the session ID and has a limited lifetime.
func (s *Sessions) NewCSRFToken(sessionID uuid.UUID) string {
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%s:%d", sessionID.String(), timestamp)

	h := hmac.New(sha256.New, s.hmacSecret)
	h.Write([]byte(message))
	signature := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%d:%s", timestamp, signature)
}

// CheckCSRF verifies the token signature and checks expiration.
// Returns nil on success, or a specific error describing the failure.
func (s *Sessions) CheckCSRF(sessionID uuid.UUID, token string) error {
	if token == "" {
		return ErrCSRFRequired
	}

	// Parse "timestamp:signature" format
	parts := strings.SplitN(token, ":", 2)
	if len(parts) != 2 {
		return ErrCSRFMalformed
	}

	timestamp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return ErrCSRFMalformed
	}

	// Check expiration (with clock skew tolerance)
	age := time.Since(time.Unix(timestamp, 0))
	if age > CSRFTokenTTL {
		return ErrCSRFExpired
	}
	if age < -CSRFClockSkew {
		return ErrCSRFInvalid // Future timestamp = tampering
	}

	// Verify HMAC signature using constant-time comparison
	message := fmt.Sprintf("%s:%d", sessionID.String(), timestamp)
	h := hmac.New(sha256.New, s.hmacSecret)
	h.Write([]byte(message))
	expectedSig := base64.URLEncoding.EncodeToString(h.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expectedSig)) != 1 {
		return ErrCSRFInvalid
	}

	return nil
}

// Store returns the underlying session store for direct access.
// Use sparingly - prefer using Sessions methods where possible.
func (s *Sessions) Store() *session.Store {
	return s.store
}

// List handles GET /genui/sessions - returns HTML session list for sidebar.
// Pure HTMX: Returns HTML fragment, not JSON.
// NOTE: This returns the session-list div content for HTMX OOB swaps.
func (s *Sessions) List(w http.ResponseWriter, r *http.Request) {
	// Get all sessions (no pagination for sidebar, limit 100)
	sessions, err := s.store.ListSessions(r.Context(), 100, 0)
	if err != nil {
		http.Error(w, "Failed to load sessions", http.StatusInternalServerError)
		return
	}

	// Get active session ID from query param (optional)
	activeID := uuid.Nil
	if activeIDStr := r.URL.Query().Get("active"); activeIDStr != "" {
		if parsedID, parseErr := uuid.Parse(activeIDStr); parseErr == nil {
			activeID = parsedID
		}
	}

	// Convert to component.SessionItem
	items := make([]component.SessionItem, len(sessions))
	for i, sess := range sessions {
		items[i] = component.SessionItem{
			ID:        sess.ID,
			Title:     sess.Title,
			UpdatedAt: sess.UpdatedAt,
		}
	}

	// Return session-list div (for OOB swap targeting #session-list)
	w.Header().Set("Content-Type", "text/html")
	if !s.writeHTML(w, `<div id="session-list" role="navigation" aria-live="polite" aria-atomic="false" class="flex-1 overflow-y-auto p-2">`) {
		return
	}

	if len(items) == 0 {
		if !s.writeHTML(w, `<div class="px-4 py-8 text-center text-gray-500 dark:text-gray-400">No sessions yet</div>`) {
			return
		}
	} else {
		for _, item := range items {
			if err := component.SessionListItem(component.SessionItemProps{
				Session: item,
				Active:  item.ID == activeID,
			}).Render(r.Context(), w); err != nil {
				http.Error(w, "Failed to render session item", http.StatusInternalServerError)
				return
			}
		}
	}

	_ = s.writeHTML(w, `</div>`)
}

// Create handles POST /genui/sessions - creates new session and redirects.
// Pure HTMX: Uses HX-Redirect header for client-side navigation.
func (s *Sessions) Create(w http.ResponseWriter, r *http.Request) {
	// CSRF validation first
	sessionID, err := s.ID(r)
	if err != nil {
		// No existing session - get or create one for CSRF token validation
		sessionID, err = s.GetOrCreate(w, r)
		if err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}
	}

	csrfToken := r.FormValue("csrf_token")
	if csrfErr := s.CheckCSRF(sessionID, csrfToken); csrfErr != nil {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Create new chat session
	newSession, err := s.store.CreateSession(r.Context(), "", "", "")
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Use standard HTTP 303 redirect (progressive enhancement compatible)
	// HTMX will intercept and navigate without full page reload
	// Non-HTMX browsers will perform standard redirect
	http.Redirect(w, r, "/genui?session="+newSession.ID.String(), http.StatusSeeOther)
}

// Delete handles DELETE /genui/sessions/:id - deletes session and returns updated list.
// Pure HTMX: Returns fresh session list for OOB swap, removing deleted item.
func (s *Sessions) Delete(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	if sessionID == "" {
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}

	// Parse UUID
	id, parseErr := uuid.Parse(sessionID)
	if parseErr != nil {
		http.Error(w, "Invalid session ID", http.StatusBadRequest)
		return
	}

	// Delete session (cascade deletes all messages)
	if deleteErr := s.store.DeleteSession(r.Context(), id); deleteErr != nil {
		http.Error(w, "Failed to delete session", http.StatusInternalServerError)
		return
	}

	// OOB swap pattern: Return updated session list
	sessions, err := s.store.ListSessions(r.Context(), 100, 0)
	if err != nil {
		w.WriteHeader(http.StatusNoContent) // Fallback: just remove element
		return
	}

	// Convert to component.SessionItem
	items := make([]component.SessionItem, len(sessions))
	for i, sess := range sessions {
		items[i] = component.SessionItem{
			ID:        sess.ID,
			Title:     sess.Title,
			UpdatedAt: sess.UpdatedAt,
		}
	}

	// Render fresh session list with deleted item removed (OOB swap)
	w.Header().Set("Content-Type", "text/html")
	if !s.writeHTML(w, `<div id="session-list" role="navigation" aria-live="polite" aria-atomic="false" class="flex-1 overflow-y-auto p-2" hx-swap-oob="true">`) {
		return
	}

	if len(items) == 0 {
		if !s.writeHTML(w, `<div class="px-4 py-8 text-center text-gray-500 dark:text-gray-400">No sessions yet</div>`) {
			return
		}
	} else {
		for _, item := range items {
			if err := component.SessionListItem(component.SessionItemProps{
				Session: item,
				Active:  false, // No active session after delete
			}).Render(r.Context(), w); err != nil {
				http.Error(w, "Failed to render session item", http.StatusInternalServerError)
				return
			}
		}
	}

	_ = s.writeHTML(w, `</div>`)
}

// RegisterRoutes registers session HTTP routes on the given mux.
func (s *Sessions) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /genui/sessions", s.List)
	mux.HandleFunc("POST /genui/sessions", s.Create)
	mux.HandleFunc("DELETE /genui/sessions/{id}", s.Delete)
}

// writeHTML writes HTML content to the response writer.
// Returns false if write fails (caller should abort), true otherwise.
func (*Sessions) writeHTML(w http.ResponseWriter, html string) bool {
	if _, err := w.Write([]byte(html)); err != nil {
		// Can't call http.Error after writing started
		// Errors are logged by middleware
		return false
	}
	return true
}

func (*Sessions) setCookie(w http.ResponseWriter, sessionID uuid.UUID) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID.String(),
		Path:     "/genui",
		Secure:   true, // HTTPS only
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   SessionMaxAge,
	})
}
