package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/sqlc"
	"github.com/koopa0/koopa-cli/internal/testutil"
)

// testSecret is a 32-byte secret for testing.
var testSecret = []byte("test-secret-32-bytes-minimum!!!!")

// newTestSessionStore creates a session store for unit tests.
func newTestSessionStore(t *testing.T) *session.Store {
	t.Helper()
	dbContainer, cleanup := testutil.SetupTestDB(t)
	t.Cleanup(cleanup)

	queries := sqlc.New(dbContainer.Pool)
	return session.New(queries, dbContainer.Pool, slog.Default())
}

// testContext returns a context for testing.
func testContext(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}

func TestSessions_NewCSRFToken(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)
	sessionID := uuid.New()

	token := sessions.NewCSRFToken(sessionID)

	// Token format: "timestamp:signature"
	parts := strings.SplitN(token, ":", 2)
	require.Len(t, parts, 2, "token should have format timestamp:signature")
	assert.NotEmpty(t, parts[0], "timestamp should not be empty")
	assert.NotEmpty(t, parts[1], "signature should not be empty")
}

func TestSessions_CheckCSRF_Valid(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)
	sessionID := uuid.New()

	token := sessions.NewCSRFToken(sessionID)
	err := sessions.CheckCSRF(sessionID, token)

	assert.NoError(t, err)
}

func TestSessions_CheckCSRF_Empty(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)
	sessionID := uuid.New()

	err := sessions.CheckCSRF(sessionID, "")

	assert.ErrorIs(t, err, ErrCSRFRequired)
}

func TestSessions_CheckCSRF_Malformed(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)
	sessionID := uuid.New()

	tests := []struct {
		name  string
		token string
	}{
		{"no colon", "invalid"},
		{"colon only", ":"},
		{"non-numeric timestamp", "abc:signature"},
		{"empty timestamp", ":signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := sessions.CheckCSRF(sessionID, tt.token)
			assert.ErrorIs(t, err, ErrCSRFMalformed)
		})
	}
}

func TestSessions_CheckCSRF_WrongSession(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)
	sessionA := uuid.New()
	sessionB := uuid.New()

	tokenForA := sessions.NewCSRFToken(sessionA)

	// Try to use token from sessionA in sessionB context
	err := sessions.CheckCSRF(sessionB, tokenForA)

	assert.ErrorIs(t, err, ErrCSRFInvalid, "cross-session token must be rejected")
}

func TestSessions_CheckCSRF_TamperedSignature(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)
	sessionID := uuid.New()

	token := sessions.NewCSRFToken(sessionID)
	// Tamper with signature
	tamperedToken := token[:len(token)-1] + "X"

	err := sessions.CheckCSRF(sessionID, tamperedToken)

	assert.ErrorIs(t, err, ErrCSRFInvalid)
}

func TestSessions_CheckCSRF_TimingBoundary(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)
	sessionID := uuid.New()

	tests := []struct {
		name    string
		age     time.Duration
		wantErr error
	}{
		{"fresh token", 0, nil},
		{"1 hour old", time.Hour, nil},
		{"23 hours old", 23 * time.Hour, nil},
		{"just within TTL", 23*time.Hour + 59*time.Minute, nil},
		{"just expired", 24*time.Hour + 1*time.Second, ErrCSRFExpired},
		{"way expired", 48 * time.Hour, ErrCSRFExpired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			token := createTokenWithAge(sessions, sessionID, tt.age)
			err := sessions.CheckCSRF(sessionID, token)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSessions_CheckCSRF_FutureTimestamp(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)
	sessionID := uuid.New()

	tests := []struct {
		name    string
		future  time.Duration
		wantErr error
	}{
		{"5min in future (within skew)", 5 * time.Minute, nil},
		{"6min in future (beyond skew)", 6 * time.Minute, ErrCSRFInvalid},
		{"1 hour in future", time.Hour, ErrCSRFInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			token := createTokenWithAge(sessions, sessionID, -tt.future)
			err := sessions.CheckCSRF(sessionID, token)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Pre-session CSRF Token Tests

func TestSessions_NewPreSessionCSRFToken(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)

	token := sessions.NewPreSessionCSRFToken()

	// Token format: "pre:nonce:timestamp:signature"
	assert.True(t, strings.HasPrefix(token, preSessionPrefix), "token should have pre: prefix")
	parts := strings.SplitN(strings.TrimPrefix(token, preSessionPrefix), ":", 3)
	require.Len(t, parts, 3, "token body should have format nonce:timestamp:signature")
	assert.NotEmpty(t, parts[0], "nonce should not be empty")
	assert.NotEmpty(t, parts[1], "timestamp should not be empty")
	assert.NotEmpty(t, parts[2], "signature should not be empty")
}

func TestSessions_CheckPreSessionCSRF_Valid(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)

	token := sessions.NewPreSessionCSRFToken()
	err := sessions.CheckPreSessionCSRF(token)

	assert.NoError(t, err)
}

func TestSessions_CheckPreSessionCSRF_Empty(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)

	err := sessions.CheckPreSessionCSRF("")

	assert.ErrorIs(t, err, ErrCSRFRequired)
}

func TestSessions_CheckPreSessionCSRF_NotPreSessionToken(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)
	// Create a regular session-bound token (missing pre: prefix)
	regularToken := sessions.NewCSRFToken(uuid.New())

	err := sessions.CheckPreSessionCSRF(regularToken)

	assert.ErrorIs(t, err, ErrCSRFMalformed, "session-bound token should be rejected as pre-session token")
}

func TestSessions_CheckPreSessionCSRF_Malformed(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)

	tests := []struct {
		name  string
		token string
	}{
		{"prefix only", preSessionPrefix},
		{"missing parts", preSessionPrefix + "nonce"},
		{"only two parts", preSessionPrefix + "nonce:123"},
		{"non-numeric timestamp", preSessionPrefix + "nonce:abc:signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := sessions.CheckPreSessionCSRF(tt.token)
			assert.ErrorIs(t, err, ErrCSRFMalformed)
		})
	}
}

func TestSessions_CheckPreSessionCSRF_TamperedSignature(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)

	token := sessions.NewPreSessionCSRFToken()
	// Tamper with signature (last character)
	tamperedToken := token[:len(token)-1] + "X"

	err := sessions.CheckPreSessionCSRF(tamperedToken)

	assert.ErrorIs(t, err, ErrCSRFInvalid)
}

func TestSessions_CheckPreSessionCSRF_DifferentSecret(t *testing.T) {
	t.Parallel()

	sessionsA := NewSessions(nil, testSecret, true)
	otherSecret := []byte("other-secret-32-bytes-minimum!!!")
	sessionsB := NewSessions(nil, otherSecret, true)

	tokenFromA := sessionsA.NewPreSessionCSRFToken()

	// Try to validate with different secret
	err := sessionsB.CheckPreSessionCSRF(tokenFromA)

	assert.ErrorIs(t, err, ErrCSRFInvalid, "token from different secret should be rejected")
}

func TestIsPreSessionToken(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)

	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		{"pre-session token", sessions.NewPreSessionCSRFToken(), true},
		{"session-bound token", sessions.NewCSRFToken(uuid.New()), false},
		{"empty", "", false},
		{"random string", "random", false},
		{"prefix only", preSessionPrefix, true}, // Has prefix, even if malformed
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := IsPreSessionToken(tt.token)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSessions_ID_NoCookie(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)
	r := httptest.NewRequest("GET", "/", nil)

	_, err := sessions.ID(r)

	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestSessions_ID_InvalidUUID(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "not-a-uuid"})

	_, err := sessions.ID(r)

	assert.ErrorIs(t, err, ErrSessionInvalid)
}

func TestSessions_ID_ValidUUID(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true)
	expectedID := uuid.New()
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: expectedID.String()})

	gotID, err := sessions.ID(r)

	require.NoError(t, err)
	assert.Equal(t, expectedID, gotID)
}

func TestSessionCookie_SecurityFlags_Production(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, false) // Production mode (isDev=false)
	sessionID := uuid.New()
	w := httptest.NewRecorder()

	sessions.setCookie(w, sessionID)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]

	assert.Equal(t, SessionCookieName, c.Name, "cookie name should be generic")
	assert.Equal(t, sessionID.String(), c.Value)
	assert.True(t, c.HttpOnly, "cookie must be HttpOnly")
	assert.True(t, c.Secure, "cookie must be Secure in production")
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite, "cookie must be SameSite=Lax")
	assert.Equal(t, "/genui", c.Path, "cookie path should be /genui")
	assert.Equal(t, SessionMaxAge, c.MaxAge, "cookie should have 30 day expiry")
}

func TestSessionCookie_SecurityFlags_Development(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret, true) // Development mode (isDev=true)
	sessionID := uuid.New()
	w := httptest.NewRecorder()

	sessions.setCookie(w, sessionID)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]

	assert.Equal(t, SessionCookieName, c.Name, "cookie name should be generic")
	assert.Equal(t, sessionID.String(), c.Value)
	assert.True(t, c.HttpOnly, "cookie must be HttpOnly")
	assert.False(t, c.Secure, "cookie should NOT be Secure in dev mode (allows HTTP)")
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite, "cookie must be SameSite=Lax")
	assert.Equal(t, "/genui", c.Path, "cookie path should be /genui")
	assert.Equal(t, SessionMaxAge, c.MaxAge, "cookie should have 30 day expiry")
}

// createTokenWithAge creates a CSRF token with a specific age for testing.
// Positive age = token created in the past, negative age = future timestamp.
func createTokenWithAge(s *Sessions, sessionID uuid.UUID, age time.Duration) string {
	timestamp := time.Now().Add(-age).Unix()
	message := fmt.Sprintf("%s:%d", sessionID.String(), timestamp)

	h := hmac.New(sha256.New, s.hmacSecret)
	h.Write([]byte(message))
	signature := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%d:%s", timestamp, signature)
}

// HTTP Handler Tests for Pure HTMX handlers (List, Create, Delete, GetOrCreate).

func TestSessions_List(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)

	// Create test sessions in database
	ctx := testContext(t)
	sess1, err := store.CreateSession(ctx, "First Session", "", "")
	require.NoError(t, err)
	_, err = store.CreateSession(ctx, "Second Session", "", "")
	require.NoError(t, err)

	tests := []struct {
		name        string
		activeID    string
		wantStatus  int
		wantContain []string
	}{
		{
			name:       "list all sessions",
			activeID:   "",
			wantStatus: http.StatusOK,
			// NOTE: No longer checking for id="session-list" wrapper div
			// Sessions.List now returns only <li> items for hx-swap="innerHTML" on sidebar <ul>
			wantContain: []string{"First Session", "Second Session"},
		},
		{
			name:        "list with active session",
			activeID:    sess1.ID.String(),
			wantStatus:  http.StatusOK,
			wantContain: []string{"First Session", "Second Session"},
		},
		{
			name:        "list with invalid active ID (ignored)",
			activeID:    "not-a-uuid",
			wantStatus:  http.StatusOK,
			wantContain: []string{"First Session", "Second Session"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/genui/sessions?active="+tt.activeID, http.NoBody)
			w := httptest.NewRecorder()

			sessions.List(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			body := w.Body.String()
			for _, want := range tt.wantContain {
				assert.Contains(t, body, want)
			}
			assert.Equal(t, "text/html", w.Header().Get("Content-Type"))
		})
	}
}

func TestSessions_List_Empty(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)

	req := httptest.NewRequest(http.MethodGet, "/genui/sessions", http.NoBody)
	w := httptest.NewRecorder()

	sessions.List(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// NOTE: Changed to match sidebar.templ wording "No chats yet" instead of "No sessions yet"
	assert.Contains(t, w.Body.String(), "No chats yet")
}

func TestSessions_Create(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)

	// Create initial session to get CSRF token
	ctx := testContext(t)
	initSess, err := store.CreateSession(ctx, "", "", "")
	require.NoError(t, err)

	token := sessions.NewCSRFToken(initSess.ID)

	// Test creating new session with valid CSRF
	form := fmt.Sprintf("csrf_token=%s", token)
	req := httptest.NewRequest(http.MethodPost, "/genui/sessions", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: initSess.ID.String()})
	w := httptest.NewRecorder()

	sessions.Create(w, req)

	// Expect HTTP 303 redirect (progressive enhancement - works for HTMX and standard browsers)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "/genui?session=")
	assert.NotContains(t, w.Header().Get("Location"), initSess.ID.String(), "should create NEW session")
}

func TestSessions_Create_InvalidCSRF(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)

	// Create initial session
	ctx := testContext(t)
	initSess, err := store.CreateSession(ctx, "", "", "")
	require.NoError(t, err)

	tests := []struct {
		name       string
		csrfToken  string
		wantStatus int
	}{
		{
			name:       "missing CSRF token",
			csrfToken:  "",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "invalid CSRF token",
			csrfToken:  "invalid-token",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "expired CSRF token",
			csrfToken:  createTokenWithAge(sessions, initSess.ID, 25*time.Hour),
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := fmt.Sprintf("csrf_token=%s", tt.csrfToken)
			req := httptest.NewRequest(http.MethodPost, "/genui/sessions", strings.NewReader(form))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: initSess.ID.String()})
			w := httptest.NewRecorder()

			sessions.Create(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestSessions_Delete(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)

	// Create test session
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "To Delete", "", "")
	require.NoError(t, err)

	// Delete it (NOT current session - no cookie)
	req := httptest.NewRequest(http.MethodDelete, "/genui/sessions/"+sess.ID.String(), http.NoBody)
	req.SetPathValue("id", sess.ID.String())
	w := httptest.NewRecorder()

	sessions.Delete(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/html", w.Header().Get("Content-Type"))
	// Should NOT redirect when deleting non-current session
	assert.Empty(t, w.Header().Get("HX-Redirect"), "should NOT redirect when deleting non-current session")

	// Body should contain htmx.trigger for sidebar refresh (with defensive check)
	body := w.Body.String()
	assert.Contains(t, body, "htmx.trigger(document.body, 'sidebar-refresh')")

	// Verify session was deleted from database
	_, err = store.GetSession(ctx, sess.ID)
	assert.Error(t, err, "session should be deleted")
}

func TestSessions_Delete_CurrentSession(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)

	// Create test session
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Current Session", "", "")
	require.NoError(t, err)

	// Delete current session (with session cookie)
	req := httptest.NewRequest(http.MethodDelete, "/genui/sessions/"+sess.ID.String(), http.NoBody)
	req.SetPathValue("id", sess.ID.String())
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w := httptest.NewRecorder()

	sessions.Delete(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Should redirect to /genui when deleting current session
	assert.Equal(t, "/genui", w.Header().Get("HX-Redirect"), "should redirect when deleting current session")

	// Verify session was deleted from database
	_, err = store.GetSession(ctx, sess.ID)
	assert.Error(t, err, "session should be deleted")
}

func TestSessions_Delete_InvalidID(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)

	tests := []struct {
		name       string
		sessionID  string
		wantStatus int
	}{
		{
			name:       "missing session ID",
			sessionID:  "",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid UUID",
			sessionID:  "not-a-uuid",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/genui/sessions/"+tt.sessionID, http.NoBody)
			req.SetPathValue("id", tt.sessionID)
			w := httptest.NewRecorder()

			sessions.Delete(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestSessions_Delete_DialogID(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)

	tests := []struct {
		name       string
		dialogID   string
		wantScript bool
		wantSafe   bool // body should NOT contain XSS payload unescaped
		xssPayload string
	}{
		{
			name:       "valid dialog ID returns close script",
			dialogID:   "mobile-delete-dialog-abc123",
			wantScript: true,
		},
		{
			name:       "valid dialog ID with hyphens and underscores",
			dialogID:   "desktop_delete-dialog_session-123",
			wantScript: true,
		},
		{
			name:       "empty dialog ID returns no script",
			dialogID:   "",
			wantScript: false,
		},
		{
			name:       "XSS injection is blocked",
			dialogID:   "'); alert('XSS'); //",
			wantScript: false, // invalid chars means no script returned
			wantSafe:   true,
			xssPayload: "alert('XSS')",
		},
		{
			name:       "HTML injection is blocked",
			dialogID:   "<script>alert(1)</script>",
			wantScript: false, // invalid chars means no dialog close script
			wantSafe:   true,
			xssPayload: "alert(1)", // Verify the attacker payload is not executed
		},
		{
			name:       "SQL injection is blocked",
			dialogID:   "'; DROP TABLE sessions--",
			wantScript: false, // invalid chars means no script returned
			wantSafe:   true,
			xssPayload: "DROP TABLE",
		},
		{
			name:       "dialog ID too long is blocked",
			dialogID:   strings.Repeat("a", 101),
			wantScript: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test session for each test
			ctx := testContext(t)
			sess, err := store.CreateSession(ctx, "To Delete", "", "")
			require.NoError(t, err)

			// Send dialog_id via query parameter (as HTMX hx-vals would be URL encoded)
			// This is more reliable than body for DELETE requests in Go
			reqURL := "/genui/sessions/" + sess.ID.String()
			if tt.dialogID != "" {
				reqURL += "?dialog_id=" + url.QueryEscape(tt.dialogID)
			}

			req := httptest.NewRequest(http.MethodDelete, reqURL, http.NoBody)
			req.SetPathValue("id", sess.ID.String())
			w := httptest.NewRecorder()

			sessions.Delete(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			body := w.Body.String()
			// Script is always present (for htmx.trigger sidebar-refresh)
			assert.Contains(t, body, "<script>", "should return script")
			assert.Contains(t, body, "htmx.trigger(document.body, 'sidebar-refresh')", "should trigger sidebar refresh")

			if tt.wantScript {
				// Should contain el-dialog hide() call
				assert.Contains(t, body, "elDialog.hide()", "should contain el-dialog hide call")
				assert.Contains(t, body, tt.dialogID, "should contain dialog ID")
			}

			if tt.wantSafe && tt.xssPayload != "" {
				assert.NotContains(t, body, tt.xssPayload, "XSS payload should not appear in body")
			}
		})
	}
}

func TestIsValidDialogID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		id    string
		valid bool
	}{
		{"valid simple", "dialog-123", true},
		{"valid with underscores", "my_dialog_id", true},
		{"valid alphanumeric", "Dialog123", true},
		{"valid mixed", "mobile-delete_dialog-abc123", true},
		{"empty string", "", false},
		{"too long", strings.Repeat("a", 101), false},
		{"max length", strings.Repeat("a", 100), true},
		{"contains space", "dialog 123", false},
		{"contains quote", "dialog'123", false},
		{"contains double quote", "dialog\"123", false},
		{"contains angle bracket", "dialog<123", false},
		{"contains semicolon", "dialog;123", false},
		{"contains parenthesis", "dialog(123)", false},
		{"XSS payload", "'); alert('XSS'); //", false},
		{"HTML tag", "<script>", false},
		{"SQL injection", "'; DROP TABLE--", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isValidDialogID(tt.id)
			if got != tt.valid {
				t.Errorf("isValidDialogID(%q) = %v, want %v", tt.id, got, tt.valid)
			}
		})
	}
}

func TestSessions_GetOrCreate_ExistingSession(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)

	// Create session in database
	ctx := testContext(t)
	existingSess, err := store.CreateSession(ctx, "Existing", "", "")
	require.NoError(t, err)

	// Request with existing session cookie
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: existingSess.ID.String()})
	w := httptest.NewRecorder()

	sessionID, err := sessions.GetOrCreate(w, req.WithContext(ctx))

	require.NoError(t, err)
	assert.Equal(t, existingSess.ID, sessionID, "should return existing session ID")

	// Verify cookie was refreshed
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, SessionCookieName, cookies[0].Name)
	assert.Equal(t, existingSess.ID.String(), cookies[0].Value)
}

func TestSessions_GetOrCreate_NewSession(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)

	// Request without session cookie
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	w := httptest.NewRecorder()

	sessionID, err := sessions.GetOrCreate(w, req.WithContext(testContext(t)))

	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, sessionID, "should create new session")

	// Verify cookie was set
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, SessionCookieName, cookies[0].Name)
	assert.Equal(t, sessionID.String(), cookies[0].Value)
}

func TestSessions_GetOrCreate_StaleSession(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)

	// Create stale session ID (not in database)
	staleID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: staleID.String()})
	w := httptest.NewRecorder()

	sessionID, err := sessions.GetOrCreate(w, req.WithContext(testContext(t)))

	require.NoError(t, err)
	assert.NotEqual(t, staleID, sessionID, "should create new session when stale")

	// Verify new cookie was set
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, sessionID.String(), cookies[0].Value)
}
