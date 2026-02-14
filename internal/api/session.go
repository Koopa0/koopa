package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/koopa0/koopa/internal/session"
)

// Sentinel errors for session/CSRF operations.
var (
	// ErrSessionCookieNotFound is returned when the session cookie is absent from the request.
	ErrSessionCookieNotFound = errors.New("session cookie not found")
	// ErrSessionInvalid is returned when the session cookie value is not a valid UUID.
	ErrSessionInvalid = errors.New("session ID invalid")
	// ErrCSRFRequired is returned when a state-changing request has no CSRF token.
	ErrCSRFRequired = errors.New("csrf token required")
	// ErrCSRFInvalid is returned when the CSRF token signature does not match.
	ErrCSRFInvalid = errors.New("csrf token invalid")
	// ErrCSRFExpired is returned when the CSRF token timestamp exceeds csrfTokenTTL.
	ErrCSRFExpired = errors.New("csrf token expired")
	// ErrCSRFMalformed is returned when the CSRF token format cannot be parsed.
	ErrCSRFMalformed = errors.New("csrf token malformed")
)

// Pre-session CSRF token prefix to distinguish from user-bound tokens.
const preSessionPrefix = "pre:"

// Cookie and CSRF configuration.
const (
	sessionCookieName    = "sid"
	userCookieName       = "uid"
	csrfTokenTTL         = 24 * time.Hour
	cookieMaxAge         = 30 * 24 * 3600 // 30 days in seconds
	csrfClockSkew        = 5 * time.Minute
	messagesDefaultLimit = 100
	sessionsDefaultLimit = 50
)

// sessionManager handles session cookies, user identity, and CSRF token operations.
type sessionManager struct {
	store      *session.Store
	hmacSecret []byte
	isDev      bool
	logger     *slog.Logger
}

// SessionID extracts the active session ID from the sid cookie.
func (*sessionManager) SessionID(r *http.Request) (uuid.UUID, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return uuid.Nil, ErrSessionCookieNotFound
	}

	sessionID, err := uuid.Parse(cookie.Value)
	if err != nil {
		return uuid.Nil, ErrSessionInvalid
	}

	return sessionID, nil
}

// UserID extracts the user identity from the uid cookie.
// Returns empty string if no uid cookie is present.
func (*sessionManager) UserID(r *http.Request) string {
	cookie, err := r.Cookie(userCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// NewCSRFToken creates an HMAC-based token bound to the user ID.
// Format: "timestamp:signature"
func (sm *sessionManager) NewCSRFToken(userID string) string {
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%s:%d", userID, timestamp)

	h := hmac.New(sha256.New, sm.hmacSecret)
	h.Write([]byte(message))
	signature := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%d:%s", timestamp, signature)
}

// CheckCSRF verifies a user-bound CSRF token.
func (sm *sessionManager) CheckCSRF(userID, token string) error {
	if token == "" {
		return ErrCSRFRequired
	}

	parts := strings.SplitN(token, ":", 2)
	if len(parts) != 2 {
		return ErrCSRFMalformed
	}

	timestamp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return ErrCSRFMalformed
	}

	age := time.Since(time.Unix(timestamp, 0))
	if age > csrfTokenTTL {
		return ErrCSRFExpired
	}
	if age < -csrfClockSkew {
		return ErrCSRFInvalid
	}

	message := fmt.Sprintf("%s:%d", userID, timestamp)
	h := hmac.New(sha256.New, sm.hmacSecret)
	h.Write([]byte(message))
	expectedSig := base64.URLEncoding.EncodeToString(h.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expectedSig)) != 1 {
		return ErrCSRFInvalid
	}

	return nil
}

// NewPreSessionCSRFToken creates an HMAC-based token for pre-session state.
// Format: "pre:nonce:timestamp:signature"
func (sm *sessionManager) NewPreSessionCSRFToken() string {
	nonce := uuid.New().String()
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%s:%d", nonce, timestamp)

	h := hmac.New(sha256.New, sm.hmacSecret)
	h.Write([]byte(message))
	signature := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s%s:%d:%s", preSessionPrefix, nonce, timestamp, signature)
}

// CheckPreSessionCSRF verifies a pre-session CSRF token.
func (sm *sessionManager) CheckPreSessionCSRF(token string) error {
	if token == "" {
		return ErrCSRFRequired
	}

	if !strings.HasPrefix(token, preSessionPrefix) {
		return ErrCSRFMalformed
	}

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

	age := time.Since(time.Unix(timestamp, 0))
	if age > csrfTokenTTL {
		return ErrCSRFExpired
	}
	if age < -csrfClockSkew {
		return ErrCSRFInvalid
	}

	message := fmt.Sprintf("%s:%d", nonce, timestamp)
	h := hmac.New(sha256.New, sm.hmacSecret)
	h.Write([]byte(message))
	expectedSig := base64.URLEncoding.EncodeToString(h.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expectedSig)) != 1 {
		return ErrCSRFInvalid
	}

	return nil
}

// requireOwnership verifies the requested session belongs to the caller.
// Uses owner_id from the database to support multi-session ownership.
// Returns the verified session ID and true, or writes an error response and returns false.
func (sm *sessionManager) requireOwnership(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	idStr := r.PathValue("id")
	if idStr == "" {
		WriteError(w, http.StatusBadRequest, "missing_id", "session ID required", sm.logger)
		return uuid.Nil, false
	}

	targetID, err := uuid.Parse(idStr)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_id", "invalid session ID", sm.logger)
		return uuid.Nil, false
	}

	userID, ok := userIDFromContext(r.Context())
	if !ok || userID == "" {
		WriteError(w, http.StatusForbidden, "forbidden", "user identity required", sm.logger)
		return uuid.Nil, false
	}

	// Verify session exists and is owned by this user
	sess, err := sm.store.Session(r.Context(), targetID)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "not_found", "session not found", sm.logger)
			return uuid.Nil, false
		}
		sm.logger.Error("checking session ownership", "error", err, "session_id", targetID)
		WriteError(w, http.StatusInternalServerError, "get_failed", "failed to verify session", sm.logger)
		return uuid.Nil, false
	}

	if sess.OwnerID != userID {
		sm.logger.Warn("session ownership check failed",
			"target", targetID,
			"owner", sess.OwnerID,
			"caller", userID,
			"path", r.URL.Path,
		)
		WriteError(w, http.StatusForbidden, "forbidden", "session access denied", sm.logger)
		return uuid.Nil, false
	}

	return targetID, true
}

func (sm *sessionManager) setSessionCookie(w http.ResponseWriter, sessionID uuid.UUID) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID.String(),
		Path:     "/",
		Secure:   !sm.isDev,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   cookieMaxAge,
	})
}

func (sm *sessionManager) setUserCookie(w http.ResponseWriter, userID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     userCookieName,
		Value:    userID,
		Path:     "/",
		Secure:   !sm.isDev,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   cookieMaxAge,
	})
}

// csrfToken handles GET /api/v1/csrf-token — provisions a CSRF token.
// Returns a user-bound token if uid cookie exists, otherwise a pre-session token.
func (sm *sessionManager) csrfToken(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromContext(r.Context())
	if ok && userID != "" {
		WriteJSON(w, http.StatusOK, map[string]string{
			"csrfToken": sm.NewCSRFToken(userID),
		}, sm.logger)
		return
	}

	WriteJSON(w, http.StatusOK, map[string]string{
		"csrfToken": sm.NewPreSessionCSRFToken(),
	}, sm.logger)
}

// listSessions handles GET /api/v1/sessions — returns all sessions owned by the caller.
func (sm *sessionManager) listSessions(w http.ResponseWriter, r *http.Request) {
	type sessionItem struct {
		ID        string `json:"id"`
		Title     string `json:"title"`
		UpdatedAt string `json:"updatedAt"`
	}

	userID, ok := userIDFromContext(r.Context())
	if !ok || userID == "" {
		WriteJSON(w, http.StatusOK, []sessionItem{}, sm.logger)
		return
	}

	sessions, err := sm.store.Sessions(r.Context(), userID, sessionsDefaultLimit, 0)
	if err != nil {
		sm.logger.Error("listing sessions", "error", err, "user_id", userID)
		WriteError(w, http.StatusInternalServerError, "list_failed", "failed to list sessions", sm.logger)
		return
	}

	items := make([]sessionItem, len(sessions))
	for i, sess := range sessions {
		items[i] = sessionItem{
			ID:        sess.ID.String(),
			Title:     sess.Title,
			UpdatedAt: sess.UpdatedAt.Format(time.RFC3339),
		}
	}

	WriteJSON(w, http.StatusOK, items, sm.logger)
}

// createSession handles POST /api/v1/sessions — creates a new session.
func (sm *sessionManager) createSession(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromContext(r.Context())
	if !ok || userID == "" {
		WriteError(w, http.StatusBadRequest, "user_required", "user identity required", sm.logger)
		return
	}

	sess, err := sm.store.CreateSession(r.Context(), userID, "")
	if err != nil {
		sm.logger.Error("creating session", "error", err)
		WriteError(w, http.StatusInternalServerError, "create_failed", "failed to create session", sm.logger)
		return
	}

	sm.setSessionCookie(w, sess.ID)

	WriteJSON(w, http.StatusCreated, map[string]string{
		"id":        sess.ID.String(),
		"csrfToken": sm.NewCSRFToken(userID),
	}, sm.logger)
}

// getSession handles GET /api/v1/sessions/{id} — returns a single session.
// Requires ownership: the session must belong to the caller.
func (sm *sessionManager) getSession(w http.ResponseWriter, r *http.Request) {
	id, ok := sm.requireOwnership(w, r)
	if !ok {
		return
	}

	sess, err := sm.store.Session(r.Context(), id)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "not_found", "session not found", sm.logger)
			return
		}
		sm.logger.Error("getting session", "error", err, "session_id", id)
		WriteError(w, http.StatusInternalServerError, "get_failed", "failed to get session", sm.logger)
		return
	}

	WriteJSON(w, http.StatusOK, map[string]string{
		"id":        sess.ID.String(),
		"title":     sess.Title,
		"createdAt": sess.CreatedAt.Format(time.RFC3339),
		"updatedAt": sess.UpdatedAt.Format(time.RFC3339),
	}, sm.logger)
}

// getSessionMessages handles GET /api/v1/sessions/{id}/messages — returns messages for a session.
// Requires ownership: the session must belong to the caller.
func (sm *sessionManager) getSessionMessages(w http.ResponseWriter, r *http.Request) {
	id, ok := sm.requireOwnership(w, r)
	if !ok {
		return
	}

	messages, err := sm.store.Messages(r.Context(), id, messagesDefaultLimit, 0)
	if err != nil {
		sm.logger.Error("getting messages", "error", err, "session_id", id)
		WriteError(w, http.StatusInternalServerError, "get_failed", "failed to get messages", sm.logger)
		return
	}

	type messageItem struct {
		ID        string `json:"id"`
		Role      string `json:"role"`
		Content   string `json:"content"`
		CreatedAt string `json:"createdAt"`
	}

	items := make([]messageItem, len(messages))
	for i, msg := range messages {
		// Extract text content from ai.Part slice
		var text string
		for _, part := range msg.Content {
			if part != nil {
				text += part.Text
			}
		}

		items[i] = messageItem{
			ID:        msg.ID.String(),
			Role:      msg.Role,
			Content:   text,
			CreatedAt: msg.CreatedAt.Format(time.RFC3339),
		}
	}

	WriteJSON(w, http.StatusOK, items, sm.logger)
}

// deleteSession handles DELETE /api/v1/sessions/{id} — deletes a session.
// Requires ownership: the session must belong to the caller.
func (sm *sessionManager) deleteSession(w http.ResponseWriter, r *http.Request) {
	id, ok := sm.requireOwnership(w, r)
	if !ok {
		return
	}

	if err := sm.store.DeleteSession(r.Context(), id); err != nil {
		sm.logger.Error("deleting session", "error", err, "session_id", id)
		WriteError(w, http.StatusInternalServerError, "delete_failed", "failed to delete session", sm.logger)
		return
	}

	WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"}, sm.logger)
}
