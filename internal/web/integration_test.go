//go:build integration

package web_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/sqlc"
	"github.com/koopa0/koopa-cli/internal/testutil"
	"github.com/koopa0/koopa-cli/internal/web"
	"github.com/koopa0/koopa-cli/internal/web/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMiddlewareStack_SessionAndCSRF verifies the full middleware chain integration.
func TestMiddlewareStack_SessionAndCSRF(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Setup test database
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := session.New(sqlc.New(dbContainer.Pool), dbContainer.Pool, testutil.DiscardLogger())
	sessions := handlers.NewSessions(store, []byte("test-secret-at-least-32-bytes-long!!!"), true)
	logger := testutil.DiscardLogger()

	// Test handler that verifies session ID in context
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID, ok := web.GetSessionID(r.Context())
		if !ok {
			t.Error("Session ID not found in request context")
		}
		if sessionID == uuid.Nil {
			t.Error("Session ID is nil")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	// Apply middleware stack in correct order (innermost to outermost)
	// Execution order: Recovery → Logging → Session → CSRF → Handler
	handler := web.RecoveryMiddleware(logger)(
		web.LoggingMiddleware(logger)(
			web.RequireSession(sessions, logger)(
				web.RequireCSRF(sessions, logger)(testHandler),
			),
		),
	)

	t.Run("POST with valid CSRF token", func(t *testing.T) {
		// Step 1: Create session and get CSRF token
		rec1 := httptest.NewRecorder()
		req1 := httptest.NewRequest(http.MethodGet, "/test", nil)

		// Create session directly
		sessionID, err := sessions.GetOrCreate(rec1, req1)
		require.NoError(t, err)

		// Extract session cookie
		cookies := rec1.Result().Cookies()
		require.NotEmpty(t, cookies, "Session cookie should be set")
		sessionCookie := cookies[0]

		// Generate CSRF token for this session
		csrfToken := sessions.NewCSRFToken(sessionID)
		require.NotEmpty(t, csrfToken, "CSRF token should be generated")

		// Step 2: Make POST request with session cookie and CSRF token
		form := url.Values{}
		form.Set("csrf_token", csrfToken)
		form.Set("content", "test message")

		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req2.AddCookie(sessionCookie)

		handler.ServeHTTP(rec2, req2)

		// Verify success
		assert.Equal(t, http.StatusOK, rec2.Code)
		assert.Equal(t, "success", rec2.Body.String())
	})

	t.Run("POST without CSRF token fails", func(t *testing.T) {
		// Create session first
		rec1 := httptest.NewRecorder()
		req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
		_, err := sessions.GetOrCreate(rec1, req1)
		require.NoError(t, err)

		sessionCookie := rec1.Result().Cookies()[0]

		// POST without CSRF token
		form := url.Values{}
		form.Set("content", "test message")
		// No csrf_token field

		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req2.AddCookie(sessionCookie)

		handler.ServeHTTP(rec2, req2)

		// Verify CSRF validation failure
		assert.Equal(t, http.StatusForbidden, rec2.Code)
		assert.Contains(t, rec2.Body.String(), "CSRF validation failed")
	})

	t.Run("POST with invalid CSRF token fails", func(t *testing.T) {
		// Create session
		rec1 := httptest.NewRecorder()
		req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
		_, err := sessions.GetOrCreate(rec1, req1)
		require.NoError(t, err)

		sessionCookie := rec1.Result().Cookies()[0]

		// POST with invalid CSRF token
		form := url.Values{}
		form.Set("csrf_token", "invalid-token-12345")
		form.Set("content", "test message")

		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req2.AddCookie(sessionCookie)

		handler.ServeHTTP(rec2, req2)

		// Verify CSRF validation failure
		assert.Equal(t, http.StatusForbidden, rec2.Code)
	})

	t.Run("GET request bypasses CSRF check", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		handler.ServeHTTP(rec, req)

		// Should succeed without CSRF token
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// TestMiddlewareStack_PanicRecovery verifies recovery middleware integration.
func TestMiddlewareStack_PanicRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := session.New(sqlc.New(dbContainer.Pool), dbContainer.Pool, testutil.DiscardLogger())
	sessions := handlers.NewSessions(store, []byte("test-secret-at-least-32-bytes-long!!!"), true)
	logger := testutil.DiscardLogger()

	// Handler that panics
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("intentional test panic")
	})

	// Full middleware stack with recovery
	handler := web.RecoveryMiddleware(logger)(
		web.LoggingMiddleware(logger)(
			web.RequireSession(sessions, logger)(panicHandler),
		),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	// Should not crash the server
	handler.ServeHTTP(rec, req)

	// Verify 500 error response
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "Internal Server Error")
}

// TestMiddlewareStack_SessionPersistence verifies session cookie persistence.
func TestMiddlewareStack_SessionPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := session.New(sqlc.New(dbContainer.Pool), dbContainer.Pool, testutil.DiscardLogger())
	sessions := handlers.NewSessions(store, []byte("test-secret-at-least-32-bytes-long!!!"), true)

	// First request: Creates session
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	firstSessionID, err := sessions.GetOrCreate(rec1, req1)
	require.NoError(t, err)

	cookies1 := rec1.Result().Cookies()
	require.NotEmpty(t, cookies1)

	// Second request: Reuses same session with cookie
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.AddCookie(cookies1[0])
	secondSessionID, err := sessions.GetOrCreate(rec2, req2)
	require.NoError(t, err)

	// Verify same session ID was reused
	assert.Equal(t, firstSessionID, secondSessionID,
		"Session ID should persist across requests")
}
