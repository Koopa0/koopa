package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMode_Toggle_ChatMode(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)

	csrfToken := sessions.NewCSRFToken(sess.ID)

	// HTMX request to toggle to chat mode
	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("mode", "chat")

	req := httptest.NewRequest(http.MethodPost, "/genui/mode", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w := httptest.NewRecorder()

	mode.Toggle(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "mode-changed", w.Header().Get("HX-Trigger"))
	assert.Equal(t, "text/html", w.Header().Get("Content-Type"))

	updatedSess, err := store.GetSession(ctx, sess.ID)
	require.NoError(t, err)
	assert.False(t, updatedSess.CanvasMode, "chat mode should set canvas_mode to false")
}

func TestMode_Toggle_CanvasMode(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)

	csrfToken := sessions.NewCSRFToken(sess.ID)

	// HTMX request to toggle to canvas mode
	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("mode", "canvas")

	req := httptest.NewRequest(http.MethodPost, "/genui/mode", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w := httptest.NewRecorder()

	mode.Toggle(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "mode-changed", w.Header().Get("HX-Trigger"))

	updatedSess, err := store.GetSession(ctx, sess.ID)
	require.NoError(t, err)
	assert.True(t, updatedSess.CanvasMode, "canvas mode should set canvas_mode to true")
}

func TestMode_Toggle_ModeFromQueryParam(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)

	csrfToken := sessions.NewCSRFToken(sess.ID)

	// HTMX request with mode in query param (not form)
	form := url.Values{}
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/genui/mode?mode=canvas", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w := httptest.NewRecorder()

	mode.Toggle(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	updatedSess, err := store.GetSession(ctx, sess.ID)
	require.NoError(t, err)
	assert.True(t, updatedSess.CanvasMode, "query param mode=canvas should work")
}

func TestMode_Toggle_CSRFValidation_HTMX(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
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
			name:       "wrong session CSRF token",
			csrfToken:  sessions.NewCSRFToken(uuid.New()), // Different session
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "valid CSRF token",
			csrfToken:  sessions.NewCSRFToken(sess.ID),
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			form := url.Values{}
			form.Set("csrf_token", tt.csrfToken)
			form.Set("mode", "chat")

			req := httptest.NewRequest(http.MethodPost, "/genui/mode", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("HX-Request", "true")
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
			w := httptest.NewRecorder()

			mode.Toggle(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestMode_Toggle_CSRFFromQueryParam(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)

	csrfToken := sessions.NewCSRFToken(sess.ID)

	// HTMX request with CSRF token in query param instead of form
	req := httptest.NewRequest(http.MethodPost, "/genui/mode?mode=canvas&csrf_token="+csrfToken, http.NoBody)
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w := httptest.NewRecorder()

	mode.Toggle(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "CSRF token from query param should be accepted")
}

func TestMode_Toggle_NonHTMX_Redirect(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)

	// Non-HTMX request (no HX-Request header)
	form := url.Values{}
	form.Set("mode", "canvas")

	req := httptest.NewRequest(http.MethodPost, "/genui/mode", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No HX-Request header - this is a regular form submission
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w := httptest.NewRecorder()

	mode.Toggle(w, req)

	// Should redirect for progressive enhancement
	assert.Equal(t, http.StatusSeeOther, w.Code, "non-HTMX should get 303 redirect")
	assert.Equal(t, "/genui", w.Header().Get("Location"), "should redirect to /genui")

	updatedSess, err := store.GetSession(ctx, sess.ID)
	require.NoError(t, err)
	assert.True(t, updatedSess.CanvasMode, "canvas mode should be stored in database even on redirect")
}

func TestMode_Toggle_NoSession_CreatesOne(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// HTMX request without session cookie
	form := url.Values{}
	form.Set("mode", "chat")

	req := httptest.NewRequest(http.MethodPost, "/genui/mode", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	// No session cookie
	w := httptest.NewRecorder()

	mode.Toggle(w, req)

	// Should succeed and create session (no CSRF check needed when no session exists)
	assert.Equal(t, http.StatusOK, w.Code)

	// Should have session cookie
	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == SessionCookieName {
			sessionCookie = c
			break
		}
	}
	require.NotNil(t, sessionCookie, "session cookie should be created")
	assert.NotEmpty(t, sessionCookie.Value, "session ID should not be empty")
}

func TestMode_Toggle_InvalidFormData(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Send malformed form data that ParseForm will reject
	req := httptest.NewRequest(http.MethodPost, "/genui/mode", strings.NewReader("%invalid"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	mode.Toggle(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid form data")
}

func TestMode_Toggle_InvalidMode_DefaultsToChat(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)

	csrfToken := sessions.NewCSRFToken(sess.ID)

	// HTMX request with invalid mode value
	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("mode", "invalid-mode") // Not "chat" or "canvas"

	req := httptest.NewRequest(http.MethodPost, "/genui/mode", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w := httptest.NewRecorder()

	mode.Toggle(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	updatedSess, err := store.GetSession(ctx, sess.ID)
	require.NoError(t, err)
	assert.False(t, updatedSess.CanvasMode, "invalid mode should default to chat (false)")
}

func TestMode_RegisterRoutes(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})
	mux := http.NewServeMux()

	mode.RegisterRoutes(mux)

	// Verify route is registered by making a request
	req := httptest.NewRequest(http.MethodPost, "/genui/mode", http.NoBody)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Should not be 404 (route exists)
	assert.NotEqual(t, http.StatusNotFound, w.Code, "POST /genui/mode should be registered")
}

// =============================================================================
// CanvasToggle Handler Tests (per QA-Master review)
// =============================================================================

func TestMode_CanvasToggle_Enable(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session with canvas mode initially OFF
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)
	require.False(t, sess.CanvasMode, "initial canvas mode should be false")

	csrfToken := sessions.NewCSRFToken(sess.ID)

	// HTMX request to toggle canvas mode (will toggle from OFF to ON)
	form := url.Values{}
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w := httptest.NewRecorder()

	mode.CanvasToggle(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/html", w.Header().Get("Content-Type"))

	updatedSess, err := store.GetSession(ctx, sess.ID)
	require.NoError(t, err)
	assert.True(t, updatedSess.CanvasMode, "toggle should enable canvas mode in database")

	// Verify response contains button component HTML
	assert.Contains(t, w.Body.String(), "canvas-toggle", "response should contain the toggle button")
}

func TestMode_CanvasToggle_Disable(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session with canvas mode initially ON
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)
	// Enable canvas mode first
	require.NoError(t, store.UpdateCanvasMode(ctx, sess.ID, true))

	csrfToken := sessions.NewCSRFToken(sess.ID)

	// HTMX request to toggle canvas mode (will toggle from ON to OFF)
	form := url.Values{}
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w := httptest.NewRecorder()

	mode.CanvasToggle(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	updatedSess, err := store.GetSession(ctx, sess.ID)
	require.NoError(t, err)
	assert.False(t, updatedSess.CanvasMode, "toggle should disable canvas mode in database")

	assert.Contains(t, w.Body.String(), "hx-swap-oob", "response should contain OOB hide script when disabling")
}

func TestMode_CanvasToggle_CSRFValidation(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
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
			name:       "wrong session CSRF token",
			csrfToken:  sessions.NewCSRFToken(uuid.New()), // Different session
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "valid CSRF token",
			csrfToken:  sessions.NewCSRFToken(sess.ID),
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			form := url.Values{}
			form.Set("csrf_token", tt.csrfToken)

			req := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("HX-Request", "true")
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
			w := httptest.NewRecorder()

			mode.CanvasToggle(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestMode_CanvasToggle_NonHTMX_Redirect(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)

	// Non-HTMX request (no HX-Request header) - progressive enhancement
	form := url.Values{}

	req := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No HX-Request header - this is a regular form submission
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w := httptest.NewRecorder()

	mode.CanvasToggle(w, req)

	// Should redirect for progressive enhancement
	assert.Equal(t, http.StatusSeeOther, w.Code, "non-HTMX should get 303 redirect")
	assert.Equal(t, "/genui", w.Header().Get("Location"), "should redirect to /genui")

	updatedSess, err := store.GetSession(ctx, sess.ID)
	require.NoError(t, err)
	assert.True(t, updatedSess.CanvasMode, "canvas mode should be toggled in database even on redirect")
}

func TestMode_CanvasToggle_NoSession_Returns400(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// HTMX request without session cookie
	form := url.Values{}

	req := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	// No session cookie
	w := httptest.NewRecorder()

	mode.CanvasToggle(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "should return 400 when no session")
	assert.Contains(t, w.Body.String(), "session required")
}

func TestMode_CanvasToggle_InvalidFormData(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Send malformed form data that ParseForm will reject
	req := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader("%invalid"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	mode.CanvasToggle(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid form data")
}

func TestMode_CanvasToggle_SessionNotFound(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Use a non-existent session ID
	fakeSessionID := uuid.New()
	csrfToken := sessions.NewCSRFToken(fakeSessionID)

	form := url.Values{}
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: fakeSessionID.String()})
	w := httptest.NewRecorder()

	mode.CanvasToggle(w, req)

	// Should return 404 for non-existent session
	assert.Equal(t, http.StatusNotFound, w.Code, "should return 404 when session not found")
	assert.Contains(t, w.Body.String(), "session not found")
}

func TestMode_CanvasToggle_RegisterRoutes(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})
	mux := http.NewServeMux()

	mode.RegisterRoutes(mux)

	// Verify canvas-toggle route is registered
	req := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", http.NoBody)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Should not be 404 (route exists)
	assert.NotEqual(t, http.StatusNotFound, w.Code, "POST /genui/canvas-toggle should be registered")
}

// =============================================================================
// Database-specific tests
// =============================================================================

func TestMode_CanvasToggle_DatabasePersistence(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)

	csrfToken := sessions.NewCSRFToken(sess.ID)

	// Toggle canvas ON
	form := url.Values{}
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w := httptest.NewRecorder()

	mode.CanvasToggle(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Verify in database
	updatedSess, err := store.GetSession(ctx, sess.ID)
	require.NoError(t, err)
	assert.True(t, updatedSess.CanvasMode)

	// Toggle canvas OFF (second toggle)
	csrfToken2 := sessions.NewCSRFToken(sess.ID)
	form2 := url.Values{}
	form2.Set("csrf_token", csrfToken2)

	req2 := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("HX-Request", "true")
	req2.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w2 := httptest.NewRecorder()

	mode.CanvasToggle(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)

	// Verify toggled back to OFF in database
	updatedSess2, err := store.GetSession(ctx, sess.ID)
	require.NoError(t, err)
	assert.False(t, updatedSess2.CanvasMode)
}

func TestMode_CanvasToggle_OOBScriptOnlyWhenDisabling(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	ctx := testContext(t)

	t.Run("enabling does not include OOB script", func(t *testing.T) {
		// Create session with canvas OFF
		sess, err := store.CreateSession(ctx, "Test Session", "", "")
		require.NoError(t, err)

		csrfToken := sessions.NewCSRFToken(sess.ID)
		form := url.Values{}
		form.Set("csrf_token", csrfToken)

		req := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("HX-Request", "true")
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
		w := httptest.NewRecorder()

		mode.CanvasToggle(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.NotContains(t, w.Body.String(), "hx-swap-oob", "OOB script should NOT be included when enabling")
	})

	t.Run("disabling includes OOB script", func(t *testing.T) {
		// Create session with canvas ON
		sess, err := store.CreateSession(ctx, "Test Session 2", "", "")
		require.NoError(t, err)
		require.NoError(t, store.UpdateCanvasMode(ctx, sess.ID, true))

		csrfToken := sessions.NewCSRFToken(sess.ID)
		form := url.Values{}
		form.Set("csrf_token", csrfToken)

		req := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("HX-Request", "true")
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
		w := httptest.NewRecorder()

		mode.CanvasToggle(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "hx-swap-oob", "OOB script should be included when disabling")
	})
}

// =============================================================================
// UI Visual State Tests (per QA-Master review)
// Tests button appearance, ARIA attributes, and visual indicators
// =============================================================================

func TestMode_CanvasToggle_UIVisualState_Enabled(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session with canvas mode OFF (will be toggled ON)
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)

	csrfToken := sessions.NewCSRFToken(sess.ID)
	form := url.Values{}
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w := httptest.NewRecorder()

	mode.CanvasToggle(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()

	// Test visual state for ENABLED canvas mode
	t.Run("has correct ARIA state", func(t *testing.T) {
		assert.Contains(t, body, `aria-checked="true"`, "should have aria-checked=true when enabled")
		assert.Contains(t, body, `role="switch"`, "should have role=switch for accessibility")
	})

	t.Run("has enabled styling classes", func(t *testing.T) {
		// Per CanvasToggle component: enabled = bg-indigo-500 text-white
		assert.Contains(t, body, "bg-indigo-500", "should have indigo background when enabled")
		assert.Contains(t, body, "text-white", "should have white text when enabled")
	})

	t.Run("has active indicator dot", func(t *testing.T) {
		// Per CanvasToggle component: white dot indicator when enabled
		assert.Contains(t, body, "size-2 rounded-full bg-white", "should have white indicator dot when enabled")
	})

	t.Run("has correct button ID and structure", func(t *testing.T) {
		assert.Contains(t, body, `id="canvas-toggle"`, "should have correct button ID")
		assert.Contains(t, body, "Canvas", "should have Canvas label")
	})

	t.Run("has accessibility label", func(t *testing.T) {
		assert.Contains(t, body, `aria-label="Enable Canvas mode`, "should have descriptive aria-label")
	})
}

func TestMode_CanvasToggle_UIVisualState_Disabled(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session with canvas mode ON (will be toggled OFF)
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)
	require.NoError(t, store.UpdateCanvasMode(ctx, sess.ID, true))

	csrfToken := sessions.NewCSRFToken(sess.ID)
	form := url.Values{}
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w := httptest.NewRecorder()

	mode.CanvasToggle(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()

	// Test visual state for DISABLED canvas mode
	t.Run("has correct ARIA state", func(t *testing.T) {
		assert.Contains(t, body, `aria-checked="false"`, "should have aria-checked=false when disabled")
	})

	t.Run("has disabled styling classes", func(t *testing.T) {
		// Per CanvasToggle component: disabled = bg-white/5 text-gray-400
		assert.Contains(t, body, "bg-white/5", "should have muted background when disabled")
		assert.Contains(t, body, "text-gray-400", "should have gray text when disabled")
	})

	t.Run("does not have active indicator dot", func(t *testing.T) {
		// When disabled, the white dot indicator should NOT be present
		// The button should NOT contain the indicator span
		assert.NotContains(t, body, "size-2 rounded-full bg-white", "should NOT have white indicator dot when disabled")
	})

	t.Run("has screen reader announcement", func(t *testing.T) {
		assert.Contains(t, body, `aria-live="polite"`, "should have aria-live region for announcements")
		assert.Contains(t, body, "Standard chat mode", "should announce disabled state")
	})
}

func TestMode_CanvasToggle_UIVisualState_HTMXAttributes(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)

	csrfToken := sessions.NewCSRFToken(sess.ID)
	form := url.Values{}
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w := httptest.NewRecorder()

	mode.CanvasToggle(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()

	// Test HTMX integration attributes
	t.Run("has HTMX post action", func(t *testing.T) {
		assert.Contains(t, body, `hx-post="/genui/canvas-toggle"`, "should POST to canvas-toggle endpoint")
	})

	t.Run("has HTMX swap behavior", func(t *testing.T) {
		assert.Contains(t, body, `hx-swap="outerHTML"`, "should swap outerHTML for full button replacement")
	})

	t.Run("has HTMX self-target", func(t *testing.T) {
		assert.Contains(t, body, `hx-target="this"`, "should target itself for replacement")
	})

	t.Run("has disabled element during request", func(t *testing.T) {
		assert.Contains(t, body, `hx-disabled-elt="this"`, "should disable during HTMX request")
	})

	t.Run("has CSRF token in hx-vals", func(t *testing.T) {
		// hx-vals should contain csrf_token
		assert.Contains(t, body, "csrf_token", "should include CSRF token in hx-vals")
	})
}

func TestMode_CanvasToggle_UIVisualState_ToggleCycle(t *testing.T) {
	t.Parallel()

	store := newTestSessionStore(t)
	sessions := NewSessions(store, testSecret, true)
	mode := NewMode(ModeDeps{Sessions: sessions})

	// Create session starting with canvas OFF
	ctx := testContext(t)
	sess, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)
	require.False(t, sess.CanvasMode, "should start with canvas off")

	// Toggle 1: OFF -> ON
	csrfToken1 := sessions.NewCSRFToken(sess.ID)
	form1 := url.Values{}
	form1.Set("csrf_token", csrfToken1)

	req1 := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form1.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req1.Header.Set("HX-Request", "true")
	req1.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w1 := httptest.NewRecorder()

	mode.CanvasToggle(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code)

	body1 := w1.Body.String()
	assert.Contains(t, body1, `aria-checked="true"`, "first toggle should enable (aria-checked=true)")
	assert.Contains(t, body1, "bg-indigo-500", "first toggle should show enabled styling")
	assert.NotContains(t, body1, "hx-swap-oob", "first toggle should NOT include OOB script")

	// Toggle 2: ON -> OFF
	csrfToken2 := sessions.NewCSRFToken(sess.ID)
	form2 := url.Values{}
	form2.Set("csrf_token", csrfToken2)

	req2 := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("HX-Request", "true")
	req2.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w2 := httptest.NewRecorder()

	mode.CanvasToggle(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)

	body2 := w2.Body.String()
	assert.Contains(t, body2, `aria-checked="false"`, "second toggle should disable (aria-checked=false)")
	assert.Contains(t, body2, "bg-white/5", "second toggle should show disabled styling")
	assert.Contains(t, body2, "hx-swap-oob", "second toggle should include OOB script")

	// Toggle 3: OFF -> ON (back to enabled)
	csrfToken3 := sessions.NewCSRFToken(sess.ID)
	form3 := url.Values{}
	form3.Set("csrf_token", csrfToken3)

	req3 := httptest.NewRequest(http.MethodPost, "/genui/canvas-toggle", strings.NewReader(form3.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req3.Header.Set("HX-Request", "true")
	req3.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID.String()})
	w3 := httptest.NewRecorder()

	mode.CanvasToggle(w3, req3)
	require.Equal(t, http.StatusOK, w3.Code)

	body3 := w3.Body.String()
	assert.Contains(t, body3, `aria-checked="true"`, "third toggle should enable again")
	assert.Contains(t, body3, "bg-indigo-500", "third toggle should show enabled styling again")
}
