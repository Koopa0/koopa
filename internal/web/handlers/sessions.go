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
	"github.com/koopa0/koopa/internal/session"
	"github.com/koopa0/koopa/internal/web/component"
)

// Sentinel errors for session/CSRF operations.
// Note: ErrSessionCookieNotFound is distinct from session.ErrSessionNotFound:
// - ErrSessionCookieNotFound: HTTP cookie missing from request (HTTP layer)
// - session.ErrSessionNotFound: session not in database (persistence layer)
var (
	ErrSessionCookieNotFound = errors.New("session cookie not found")
	ErrSessionInvalid        = errors.New("session ID invalid")
	ErrCSRFRequired          = errors.New("CSRF token required")
	ErrCSRFInvalid           = errors.New("CSRF token invalid")
	ErrCSRFExpired           = errors.New("CSRF token expired")
	ErrCSRFMalformed         = errors.New("CSRF token malformed")
)

// Pre-session CSRF token prefix to distinguish from session-bound tokens.
const preSessionPrefix = "pre:"

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
	isDev      bool // When true, Secure cookie flag is disabled for HTTP dev servers
}

// NewSessions creates a Sessions handler with the given store and HMAC secret.
// The secret must be at least 32 bytes for HMAC-SHA256 security.
// isDev should be true for local development (HTTP) to ensure cookies work without HTTPS.
func NewSessions(store *session.Store, hmacSecret []byte, isDev bool) *Sessions {
	return &Sessions{
		store:      store,
		hmacSecret: hmacSecret,
		isDev:      isDev,
	}
}

// GetOrCreate retrieves session ID from cookie/query or creates a new session.
// Session selection priority:
// 1. Query parameter "session_id" - for switching to existing sessions
// 2. Cookie - for resuming the current session
// 3. Create new - only when no existing session is found
// On success, sets/refreshes the session cookie and returns the session UUID.
func (s *Sessions) GetOrCreate(w http.ResponseWriter, r *http.Request) (uuid.UUID, error) {
	// Priority 1: Check for session_id in query parameter (for session switching)
	if sessionIDStr := r.URL.Query().Get("session_id"); sessionIDStr != "" {
		sessionID, parseErr := uuid.Parse(sessionIDStr)
		if parseErr == nil {
			// Verify session exists in database
			_, getErr := s.store.GetSession(r.Context(), sessionID)
			if getErr == nil {
				// Valid session from query param - update cookie
				s.setCookie(w, sessionID)
				return sessionID, nil
			}
			// Session not in DB, fall through to cookie/create
		}
	}

	// Priority 2: Try to get existing session from cookie
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

	// Priority 3: Create new session in database
	sess, err := s.store.CreateSession(r.Context(), "", "", "")
	if err != nil {
		return uuid.Nil, fmt.Errorf("create session: %w", err)
	}

	// Set cookie with new session ID
	s.setCookie(w, sess.ID)
	return sess.ID, nil
}

// ID extracts session ID from cookie without creating new session.
// Returns ErrSessionCookieNotFound if cookie is missing, ErrSessionInvalid if malformed.
func (*Sessions) ID(r *http.Request) (uuid.UUID, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return uuid.Nil, ErrSessionCookieNotFound
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

// NewPreSessionCSRFToken creates an HMAC-based token for pre-session state.
// Used when user hasn't interacted yet (lazy session creation).
// Format: "pre:nonce:timestamp:signature"
// The token is NOT bound to a session ID - uses random nonce instead.
func (s *Sessions) NewPreSessionCSRFToken() string {
	nonce := uuid.New().String()
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%s:%d", nonce, timestamp)

	h := hmac.New(sha256.New, s.hmacSecret)
	h.Write([]byte(message))
	signature := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s%s:%d:%s", preSessionPrefix, nonce, timestamp, signature)
}

// CheckPreSessionCSRF verifies a pre-session CSRF token.
// Returns nil on success, or a specific error describing the failure.
func (s *Sessions) CheckPreSessionCSRF(token string) error {
	if token == "" {
		return ErrCSRFRequired
	}

	// Must have pre-session prefix
	if !strings.HasPrefix(token, preSessionPrefix) {
		return ErrCSRFMalformed
	}

	// Remove prefix and parse "nonce:timestamp:signature"
	tokenBody := strings.TrimPrefix(token, preSessionPrefix)
	parts := strings.SplitN(tokenBody, ":", 3)
	if len(parts) != 3 {
		return ErrCSRFMalformed
	}

	nonce := parts[0]
	timestamp, err := strconv.ParseInt(parts[1], 10, 64)
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
	message := fmt.Sprintf("%s:%d", nonce, timestamp)
	h := hmac.New(sha256.New, s.hmacSecret)
	h.Write([]byte(message))
	expectedSig := base64.URLEncoding.EncodeToString(h.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expectedSig)) != 1 {
		return ErrCSRFInvalid
	}

	return nil
}

// IsPreSessionToken checks if a token is a pre-session token.
// Used to determine which validation method to use.
func IsPreSessionToken(token string) bool {
	return strings.HasPrefix(token, preSessionPrefix)
}

// Store returns the underlying session store for direct access.
// Use sparingly - prefer using Sessions methods where possible.
func (s *Sessions) Store() *session.Store {
	return s.store
}

// List handles GET /genui/sessions - returns HTML session list for sidebar.
// Pure HTMX: Returns HTML fragment, not JSON.
// Returns ONLY the inner content (session items) without wrapper div.
// The sidebar uses hx-swap="innerHTML" which replaces the content inside the <ul>.
// Uses ListSessionsWithMessages to only show sessions with messages or titles.
func (s *Sessions) List(w http.ResponseWriter, r *http.Request) {
	// Get sessions with messages or titles (hide empty placeholder sessions)
	sessions, err := s.store.ListSessionsWithMessages(r.Context(), 100, 0)
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

	// Return ONLY session items (no wrapper div)
	// Sidebar uses hx-swap="innerHTML" which replaces content inside <ul>
	w.Header().Set("Content-Type", "text/html")

	if len(items) == 0 {
		if !s.writeHTML(w, `<li class="text-sm text-gray-500 p-2">No chats yet</li>`) {
			return
		}
	} else {
		for _, item := range items {
			if err := component.SessionListItem(component.SessionItemProps{
				Session: item,
				Active:  item.ID == activeID,
			}).Render(r.Context(), w); err != nil {
				// Can't call http.Error - partial content may have been written
				// Error will be logged by middleware
				return
			}
		}
	}
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
	http.Redirect(w, r, "/genui?session_id="+newSession.ID.String(), http.StatusSeeOther)
}

// Delete handles DELETE /genui/sessions/:id - deletes session and triggers sidebar refresh.
// Returns JavaScript that:
// 1. Closes the @tailwindplus/elements dialog (calls hide() on el-dialog parent)
// 2. Dispatches sidebar-refresh event to body (htmx sidebars listen for this)
// 3. Redirects to /genui if deleting current session (via HX-Redirect header)
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

	// Check if deleting current session (from cookie).
	// If s.ID fails (no cookie/invalid), currentSessionID is uuid.Nil
	// which never equals a valid parsed UUID, so isDeletingCurrent = false.
	currentSessionID, _ := s.ID(r)
	isDeletingCurrent := currentSessionID == id

	// Delete session (cascade deletes all messages)
	if deleteErr := s.store.DeleteSession(r.Context(), id); deleteErr != nil {
		http.Error(w, "Failed to delete session", http.StatusInternalServerError)
		return
	}

	// If deleting current session, redirect to /genui to start fresh
	// HX-Redirect is followed by htmx client
	if isDeletingCurrent {
		w.Header().Set("HX-Redirect", "/genui")
	}

	// Get dialog ID from query params (HTMX hx-vals are URL-encoded).
	// Validate to prevent XSS - only allow safe characters.
	// ParseForm allows FormValue to check both query and body.
	_ = r.ParseForm()
	dialogID := r.FormValue("dialog_id")

	// Return script that:
	// 1. Closes the el-dialog (not native dialog.close())
	// 2. Dispatches sidebar-refresh event to body for htmx sidebars
	w.Header().Set("Content-Type", "text/html")

	// Build script with proper el-dialog closing and sidebar refresh
	script := `<script>
(function() {
	// Dispatch sidebar-refresh event to body for htmx sidebars
	// Sidebars have: hx-trigger="sidebar-refresh from:body"
	// Defensive check: htmx must be loaded (should always be true if we're here)
	if (typeof htmx !== 'undefined') {
		htmx.trigger(document.body, 'sidebar-refresh');
	}
`
	if dialogID != "" && isValidDialogID(dialogID) {
		// Close the el-dialog wrapper (not native dialog)
		// el-dialog has hide() method, native dialog has close()
		script += fmt.Sprintf(`
	// Close the delete confirmation dialog
	var dialog = document.getElementById('%s');
	if (dialog) {
		// Find el-dialog parent and call hide()
		var elDialog = dialog.closest('el-dialog');
		if (elDialog && typeof elDialog.hide === 'function') {
			elDialog.hide();
		} else if (dialog.close) {
			// Fallback to native close if no el-dialog wrapper
			dialog.close();
		}
	}
`, dialogID)
	}
	script += `})();
</script>`

	_, _ = w.Write([]byte(script))
}

// isValidDialogID validates dialog IDs to prevent XSS injection.
// Only allows alphanumeric characters, hyphens, and underscores.
// Max length 100 characters to prevent DoS via long strings.
func isValidDialogID(id string) bool {
	if id == "" || len(id) > 100 {
		return false
	}
	for _, r := range id {
		isLower := r >= 'a' && r <= 'z'
		isUpper := r >= 'A' && r <= 'Z'
		isDigit := r >= '0' && r <= '9'
		isAllowed := r == '-' || r == '_'
		if !isLower && !isUpper && !isDigit && !isAllowed {
			return false
		}
	}
	return true
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

// SetSessionCookie sets the session cookie for the given session ID.
// This is exposed for handlers that need to update the cookie after session switching.
func (s *Sessions) SetSessionCookie(w http.ResponseWriter, sessionID uuid.UUID) {
	s.setCookie(w, sessionID)
}

func (s *Sessions) setCookie(w http.ResponseWriter, sessionID uuid.UUID) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID.String(),
		Path:     "/genui",
		Secure:   !s.isDev, // HTTPS only in production; HTTP allowed in dev mode
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   SessionMaxAge,
	})
}
