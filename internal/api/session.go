package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
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
	csrfTokenTTL         = 1 * time.Hour
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
// Returns empty string if no uid cookie is present, the HMAC signature is invalid,
// or the value is not a valid UUID.
// SECURITY: Validates HMAC signature to prevent identity impersonation (F4/CWE-565),
// then validates UUID format to prevent malformed ownerIDs reaching SQL queries,
// advisory locks, and memory storage (CWE-20).
func (sm *sessionManager) UserID(r *http.Request) string {
	cookie, err := r.Cookie(userCookieName)
	if err != nil {
		return ""
	}
	uid, ok := verifySignedUID(cookie.Value, sm.hmacSecret)
	if !ok {
		return ""
	}
	if _, err := uuid.Parse(uid); err != nil {
		return ""
	}
	return uid
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

	// SECURITY: Compute and verify HMAC BEFORE timestamp checks to prevent
	// timing oracle attacks (CWE-208). If timestamp were checked first,
	// the response time difference between "expired" and "valid timestamp,
	// wrong HMAC" would leak information about valid timestamps.
	message := fmt.Sprintf("%s:%d", userID, timestamp)
	h := hmac.New(sha256.New, sm.hmacSecret)
	h.Write([]byte(message))
	expectedSig := h.Sum(nil)

	actualSig, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return ErrCSRFMalformed
	}

	if subtle.ConstantTimeCompare(actualSig, expectedSig) != 1 {
		return ErrCSRFInvalid
	}

	age := time.Since(time.Unix(timestamp, 0))
	if age > csrfTokenTTL {
		return ErrCSRFExpired
	}
	if age < -csrfClockSkew {
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

	// SECURITY: Compute and verify HMAC BEFORE timestamp checks to prevent
	// timing oracle attacks (CWE-208). See CheckCSRF for full rationale.
	message := fmt.Sprintf("%s:%d", nonce, timestamp)
	h := hmac.New(sha256.New, sm.hmacSecret)
	h.Write([]byte(message))
	expectedSig := h.Sum(nil)

	actualSig, err := base64.URLEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrCSRFMalformed
	}

	if subtle.ConstantTimeCompare(actualSig, expectedSig) != 1 {
		return ErrCSRFInvalid
	}

	age := time.Since(time.Unix(timestamp, 0))
	if age > csrfTokenTTL {
		return ErrCSRFExpired
	}
	if age < -csrfClockSkew {
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
		Value:    signUID(userID, sm.hmacSecret),
		Path:     "/",
		Secure:   !sm.isDev,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   cookieMaxAge,
	})
}

// signUID creates an HMAC-signed cookie value: "uid.base64url(HMAC-SHA256(secret, uid))".
// SECURITY: Prevents identity impersonation by making the uid cookie tamper-evident (F4/CWE-565).
func signUID(uid string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(uid))
	sig := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return uid + "." + sig
}

// verifySignedUID splits a signed cookie value and verifies the HMAC signature.
// Returns the extracted UID and true on success, or empty string and false on any failure.
func verifySignedUID(value string, secret []byte) (string, bool) {
	idx := strings.LastIndex(value, ".")
	if idx < 1 {
		return "", false
	}

	uid := value[:idx]
	sig, err := base64.URLEncoding.DecodeString(value[idx+1:])
	if err != nil {
		return "", false
	}

	h := hmac.New(sha256.New, secret)
	h.Write([]byte(uid))
	expected := h.Sum(nil)

	if subtle.ConstantTimeCompare(sig, expected) != 1 {
		return "", false
	}

	return uid, true
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

// sessionItem is the JSON representation of a session in list responses.
type sessionItem struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	MessageCount int    `json:"messageCount"`
	UpdatedAt    string `json:"updatedAt"`
}

// messageItem is the JSON representation of a message in list responses.
type messageItem struct {
	ID        string `json:"id"`
	Role      string `json:"role"`
	Content   string `json:"content"`
	CreatedAt string `json:"createdAt"`
}

// listSessions handles GET /api/v1/sessions — returns paginated sessions owned by the caller.
func (sm *sessionManager) listSessions(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromContext(r.Context())
	if !ok || userID == "" {
		WriteJSON(w, http.StatusOK, map[string]any{
			"items": []sessionItem{},
			"total": 0,
		}, sm.logger)
		return
	}

	limit := min(parseIntParam(r, "limit", sessionsDefaultLimit), 200)
	offset := parseIntParam(r, "offset", 0)
	if offset > 10000 {
		WriteError(w, http.StatusBadRequest, "invalid_offset", "offset must be 10000 or less", sm.logger)
		return
	}

	sessions, total, err := sm.store.Sessions(r.Context(), userID, limit, offset)
	if err != nil {
		sm.logger.Error("listing sessions", "error", err, "user_id", userID)
		WriteError(w, http.StatusInternalServerError, "list_failed", "failed to list sessions", sm.logger)
		return
	}

	items := make([]sessionItem, len(sessions))
	for i, sess := range sessions {
		items[i] = sessionItem{
			ID:           sess.ID.String(),
			Title:        sess.Title,
			MessageCount: sess.MessageCount,
			UpdatedAt:    sess.UpdatedAt.Format(time.RFC3339),
		}
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": total,
	}, sm.logger)
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

	msgCount, err := sm.store.CountMessagesForSession(r.Context(), id)
	if err != nil {
		sm.logger.Error("counting messages for session", "error", err, "session_id", id)
		WriteError(w, http.StatusInternalServerError, "get_failed", "failed to get session", sm.logger)
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"id":           sess.ID.String(),
		"title":        sess.Title,
		"messageCount": msgCount,
		"createdAt":    sess.CreatedAt.Format(time.RFC3339),
		"updatedAt":    sess.UpdatedAt.Format(time.RFC3339),
	}, sm.logger)
}

// getSessionMessages handles GET /api/v1/sessions/{id}/messages — returns paginated messages.
// Requires ownership: the session must belong to the caller.
func (sm *sessionManager) getSessionMessages(w http.ResponseWriter, r *http.Request) {
	id, ok := sm.requireOwnership(w, r)
	if !ok {
		return
	}

	limit := min(parseIntParam(r, "limit", messagesDefaultLimit), 1000)
	offset := parseIntParam(r, "offset", 0)
	if offset > 100000 {
		WriteError(w, http.StatusBadRequest, "invalid_offset", "offset must be 100000 or less", sm.logger)
		return
	}

	messages, total, err := sm.store.Messages(r.Context(), id, limit, offset)
	if err != nil {
		sm.logger.Error("getting messages", "error", err, "session_id", id)
		WriteError(w, http.StatusInternalServerError, "get_failed", "failed to get messages", sm.logger)
		return
	}

	items := make([]messageItem, len(messages))
	for i, msg := range messages {
		items[i] = messageItem{
			ID:        msg.ID.String(),
			Role:      msg.Role,
			Content:   msg.Text(),
			CreatedAt: msg.CreatedAt.Format(time.RFC3339),
		}
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": total,
	}, sm.logger)
}

// exportSession handles GET /api/v1/sessions/{id}/export — exports a session with all messages.
// Requires ownership: the session must belong to the caller.
// Query parameter: format=json (default) or format=markdown.
func (sm *sessionManager) exportSession(w http.ResponseWriter, r *http.Request) {
	id, ok := sm.requireOwnership(w, r)
	if !ok {
		return
	}

	data, err := sm.store.Export(r.Context(), id)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "not_found", "session not found", sm.logger)
			return
		}
		sm.logger.Error("exporting session", "error", err, "session_id", id)
		WriteError(w, http.StatusInternalServerError, "export_failed", "failed to export session", sm.logger)
		return
	}

	format := r.URL.Query().Get("format")
	switch format {
	case "markdown":
		sm.exportMarkdown(w, data)
		return
	case "", "json":
		// Default: JSON export (fall through)
	default:
		WriteError(w, http.StatusBadRequest, "invalid_format",
			"unsupported export format; use 'json' or 'markdown'", sm.logger)
		return
	}

	// Build a DTO that omits internal fields (OwnerID, SessionID, SequenceNumber).
	type exportMessage struct {
		ID        string `json:"id"`
		Role      string `json:"role"`
		Content   string `json:"content"`
		CreatedAt string `json:"createdAt"`
	}
	type exportSession struct {
		ID        string          `json:"id"`
		Title     string          `json:"title"`
		CreatedAt string          `json:"createdAt"`
		UpdatedAt string          `json:"updatedAt"`
		Messages  []exportMessage `json:"messages"`
	}

	msgs := make([]exportMessage, len(data.Messages))
	for i, msg := range data.Messages {
		msgs[i] = exportMessage{
			ID:        msg.ID.String(),
			Role:      msg.Role,
			Content:   msg.Text(),
			CreatedAt: msg.CreatedAt.Format(time.RFC3339),
		}
	}

	resp := exportSession{
		ID:        data.Session.ID.String(),
		Title:     data.Session.Title,
		CreatedAt: data.Session.CreatedAt.Format(time.RFC3339),
		UpdatedAt: data.Session.UpdatedAt.Format(time.RFC3339),
		Messages:  msgs,
	}

	// Default: JSON with Content-Disposition for download.
	w.Header().Set("Content-Disposition",
		mime.FormatMediaType("attachment", map[string]string{
			"filename": fmt.Sprintf("session-%s.json", id),
		}))
	WriteJSON(w, http.StatusOK, resp, sm.logger)
}

// titleReplacer strips newlines to prevent Markdown heading breakout.
// strings.Replacer is safe for concurrent use.
var titleReplacer = strings.NewReplacer("\n", " ", "\r", " ")

// sanitizeTitle replaces newline characters to prevent Markdown heading breakout.
func sanitizeTitle(s string) string {
	return titleReplacer.Replace(s)
}

// sanitizeMarkdownContent escapes leading Markdown structural characters
// to prevent structural injection in exported Markdown documents.
//
// Escapes: ATX headings (# ...), setext heading underlines (===, ---).
// Threat model: output is consumed as static text (editor, pandoc, etc.).
// If browser rendering is added, link/image/HTML sanitization must be implemented.
func sanitizeMarkdownContent(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		switch {
		case strings.HasPrefix(trimmed, "#"):
			// ATX heading: place backslash immediately before # to escape it.
			indent := line[:len(line)-len(trimmed)]
			lines[i] = indent + `\` + trimmed
		case isSetextUnderline(trimmed):
			// Setext heading underline: escape to prevent previous line promotion.
			indent := line[:len(line)-len(trimmed)]
			lines[i] = indent + `\` + trimmed
		}
	}
	return strings.Join(lines, "\n")
}

// isSetextUnderline reports whether trimmed (leading whitespace already removed)
// consists entirely of '=' or entirely of '-' characters (with optional trailing whitespace).
// Such lines can promote the previous paragraph to a setext heading in CommonMark.
func isSetextUnderline(trimmed string) bool {
	s := strings.TrimRight(trimmed, " \t")
	if s == "" {
		return false
	}
	return strings.Trim(s, "=") == "" || strings.Trim(s, "-") == ""
}

// exportMarkdown renders a session export as a Markdown document.
func (sm *sessionManager) exportMarkdown(w http.ResponseWriter, data *session.ExportData) {
	var b strings.Builder
	title := sanitizeTitle(data.Session.Title)
	if title == "" {
		title = "Untitled Session"
	}
	b.WriteString("# ")
	b.WriteString(title)
	b.WriteString("\n\n")

	for _, msg := range data.Messages {
		var role string
		switch msg.Role {
		case "user":
			role = "User"
		case "assistant":
			role = "Assistant"
		case "system":
			role = "System"
		case "tool":
			role = "Tool"
		default:
			role = msg.Role
		}

		b.WriteString("**")
		b.WriteString(role)
		b.WriteString("**: ")
		b.WriteString(sanitizeMarkdownContent(msg.Text()))
		b.WriteString("\n\n")
	}

	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition",
		mime.FormatMediaType("attachment", map[string]string{
			"filename": fmt.Sprintf("session-%s.md", data.Session.ID),
		}))
	if _, err := io.WriteString(w, b.String()); err != nil {
		sm.logger.Error("writing markdown export", "error", err)
	}
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
