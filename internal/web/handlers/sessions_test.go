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

	sessions := NewSessions(nil, testSecret)
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

	sessions := NewSessions(nil, testSecret)
	sessionID := uuid.New()

	token := sessions.NewCSRFToken(sessionID)
	err := sessions.CheckCSRF(sessionID, token)

	assert.NoError(t, err)
}

func TestSessions_CheckCSRF_Empty(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret)
	sessionID := uuid.New()

	err := sessions.CheckCSRF(sessionID, "")

	assert.ErrorIs(t, err, ErrCSRFRequired)
}

func TestSessions_CheckCSRF_Malformed(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret)
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

	sessions := NewSessions(nil, testSecret)
	sessionA := uuid.New()
	sessionB := uuid.New()

	tokenForA := sessions.NewCSRFToken(sessionA)

	// Try to use token from sessionA in sessionB context
	err := sessions.CheckCSRF(sessionB, tokenForA)

	assert.ErrorIs(t, err, ErrCSRFInvalid, "cross-session token must be rejected")
}

func TestSessions_CheckCSRF_TamperedSignature(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret)
	sessionID := uuid.New()

	token := sessions.NewCSRFToken(sessionID)
	// Tamper with signature
	tamperedToken := token[:len(token)-1] + "X"

	err := sessions.CheckCSRF(sessionID, tamperedToken)

	assert.ErrorIs(t, err, ErrCSRFInvalid)
}

func TestSessions_CheckCSRF_TimingBoundary(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret)
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

	sessions := NewSessions(nil, testSecret)
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

func TestSessions_ID_NoCookie(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret)
	r := httptest.NewRequest("GET", "/", nil)

	_, err := sessions.ID(r)

	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestSessions_ID_InvalidUUID(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "not-a-uuid"})

	_, err := sessions.ID(r)

	assert.ErrorIs(t, err, ErrSessionInvalid)
}

func TestSessions_ID_ValidUUID(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret)
	expectedID := uuid.New()
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: expectedID.String()})

	gotID, err := sessions.ID(r)

	require.NoError(t, err)
	assert.Equal(t, expectedID, gotID)
}

func TestSessionCookie_SecurityFlags(t *testing.T) {
	t.Parallel()

	sessions := NewSessions(nil, testSecret)
	sessionID := uuid.New()
	w := httptest.NewRecorder()

	sessions.setCookie(w, sessionID)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]

	assert.Equal(t, SessionCookieName, c.Name, "cookie name should be generic")
	assert.Equal(t, sessionID.String(), c.Value)
	assert.True(t, c.HttpOnly, "cookie must be HttpOnly")
	assert.True(t, c.Secure, "cookie must be Secure")
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
	sessions := NewSessions(store, testSecret)

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
			name:        "list all sessions",
			activeID:    "",
			wantStatus:  http.StatusOK,
			wantContain: []string{"First Session", "Second Session", `id="session-list"`},
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
	sessions := NewSessions(store, testSecret)

	req := httptest.NewRequest(http.MethodGet, "/genui/sessions", http.NoBody)
	w := httptest.NewRecorder()

	sessions.List(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "No sessions yet")
}

func TestSessions_Create(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret)

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
	sessions := NewSessions(store, testSecret)

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
	sessions := NewSessions(store, testSecret)

	// Create test session
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "To Delete", "", "")
	require.NoError(t, err)

	// Delete it
	req := httptest.NewRequest(http.MethodDelete, "/genui/sessions/"+sess.ID.String(), http.NoBody)
	req.SetPathValue("id", sess.ID.String())
	w := httptest.NewRecorder()

	sessions.Delete(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `id="session-list"`)
	assert.Contains(t, w.Body.String(), `hx-swap-oob="true"`)

	// Verify session was deleted from database
	_, err = store.GetSession(ctx, sess.ID)
	assert.Error(t, err, "session should be deleted")
}

func TestSessions_Delete_InvalidID(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret)

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

func TestSessions_GetOrCreate_ExistingSession(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret)

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
	sessions := NewSessions(store, testSecret)

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
	sessions := NewSessions(store, testSecret)

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
