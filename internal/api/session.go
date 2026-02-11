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

// Pre-session CSRF token prefix to distinguish from session-bound tokens.
const preSessionPrefix = "pre:"

// Cookie and CSRF configuration.
const (
	sessionCookieName    = "sid"
	csrfTokenTTL         = 24 * time.Hour
	sessionMaxAge        = 30 * 24 * 3600 // 30 days in seconds
	csrfClockSkew        = 5 * time.Minute
	messagesDefaultLimit = 100
)

// sessionManager handles session cookies and CSRF token operations.
type sessionManager struct {
	store      *session.Store
	hmacSecret []byte
	isDev      bool
	logger     *slog.Logger
}

// ID extracts session ID from cookie without creating a new session.
func (*sessionManager) ID(r *http.Request) (uuid.UUID, error) {
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

// NewCSRFToken creates an HMAC-based token bound to the session ID.
// Format: "timestamp:signature"
func (sm *sessionManager) NewCSRFToken(sessionID uuid.UUID) string {
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%s:%d", sessionID.String(), timestamp)

	h := hmac.New(sha256.New, sm.hmacSecret)
	h.Write([]byte(message))
	signature := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%d:%s", timestamp, signature)
}

// CheckCSRF verifies a session-bound CSRF token.
func (sm *sessionManager) CheckCSRF(sessionID uuid.UUID, token string) error {
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

	message := fmt.Sprintf("%s:%d", sessionID.String(), timestamp)
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

// requireOwnership verifies the requested session ID matches the caller's session cookie.
// Returns the verified session ID and true, or writes an error response and returns false.
// This prevents session enumeration and cross-session access.
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

	ownerID, ok := sessionIDFromContext(r.Context())
	if !ok || ownerID != targetID {
		sm.logger.Warn("session ownership check failed",
			"target", targetID,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
		)
		WriteError(w, http.StatusForbidden, "forbidden", "session access denied", sm.logger)
		return uuid.Nil, false
	}

	return targetID, true
}

func (sm *sessionManager) setCookie(w http.ResponseWriter, sessionID uuid.UUID) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID.String(),
		Path:     "/",
		Secure:   !sm.isDev,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   sessionMaxAge,
	})
}

// csrfToken handles GET /api/v1/csrf-token — provisions a CSRF token.
// Returns a session-bound token if a session exists, otherwise a pre-session token.
func (sm *sessionManager) csrfToken(w http.ResponseWriter, r *http.Request) {
	sessionID, err := sm.ID(r)
	if err == nil {
		WriteJSON(w, http.StatusOK, map[string]string{
			"csrfToken": sm.NewCSRFToken(sessionID),
		}, sm.logger)
		return
	}

	WriteJSON(w, http.StatusOK, map[string]string{
		"csrfToken": sm.NewPreSessionCSRFToken(),
	}, sm.logger)
}

// listSessions handles GET /api/v1/sessions — returns sessions owned by the caller.
// Only returns the session matching the caller's cookie (ownership enforcement).
func (sm *sessionManager) listSessions(w http.ResponseWriter, r *http.Request) {
	type sessionItem struct {
		ID        string `json:"id"`
		Title     string `json:"title"`
		UpdatedAt string `json:"updatedAt"`
	}

	sessionID, ok := sessionIDFromContext(r.Context())
	if !ok {
		// No session cookie — return empty list
		WriteJSON(w, http.StatusOK, []sessionItem{}, sm.logger)
		return
	}

	sess, err := sm.store.Session(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			WriteJSON(w, http.StatusOK, []sessionItem{}, sm.logger)
			return
		}
		sm.logger.Error("getting session", "error", err, "session_id", sessionID)
		WriteError(w, http.StatusInternalServerError, "list_failed", "failed to list sessions", sm.logger)
		return
	}

	WriteJSON(w, http.StatusOK, []sessionItem{
		{
			ID:        sess.ID.String(),
			Title:     sess.Title,
			UpdatedAt: sess.UpdatedAt.Format(time.RFC3339),
		},
	}, sm.logger)
}

// createSession handles POST /api/v1/sessions — creates a new session.
func (sm *sessionManager) createSession(w http.ResponseWriter, r *http.Request) {
	sess, err := sm.store.CreateSession(r.Context(), "")
	if err != nil {
		sm.logger.Error("creating session", "error", err)
		WriteError(w, http.StatusInternalServerError, "create_failed", "failed to create session", sm.logger)
		return
	}

	sm.setCookie(w, sess.ID)

	WriteJSON(w, http.StatusCreated, map[string]string{
		"id":        sess.ID.String(),
		"csrfToken": sm.NewCSRFToken(sess.ID),
	}, sm.logger)
}

// getSession handles GET /api/v1/sessions/{id} — returns a single session.
// Requires ownership: the session ID must match the caller's session cookie.
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
// Requires ownership: the session ID must match the caller's session cookie.
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
// Requires ownership: the session ID must match the caller's session cookie.
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
