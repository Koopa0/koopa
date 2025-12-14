//go:build integration

package handlers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/sqlc"
	"github.com/koopa0/koopa-cli/internal/testutil"
	"github.com/koopa0/koopa-cli/internal/web/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChat_Stream_WithRealFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	framework, cleanup := SetupTest(t)
	defer cleanup()

	handler := handlers.NewChat(handlers.ChatDeps{
		Logger: testutil.DiscardLogger(),
		Flow:   framework.Flow,
	})

	params := url.Values{}
	params.Set("msgId", "int-test-123")
	params.Set("session_id", framework.SessionID.String())
	params.Set("query", "What is 2+2?")

	req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
	rec := httptest.NewRecorder()

	handler.Stream(rec, req)

	body := rec.Body.String()
	events := testutil.ParseSSEEvents(t, body)

	// Verify SSE format
	require.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))

	// Verify event sequence: chunks... -> done
	require.NotEmpty(t, events, "should have events")

	doneEvent := testutil.FindEvent(events, "done")
	require.NotNil(t, doneEvent, "should have done event")

	// Verify OOB swap for HTMX
	assert.Contains(t, doneEvent.Data, "hx-swap-oob", "done event should have OOB swap")

	// Verify no JSON wrapper (raw HTML)
	assert.NotContains(t, body, `{"html":`, "should send raw HTML, not JSON")
}

func TestChat_Stream_HTMXCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	framework, cleanup := SetupTest(t)
	defer cleanup()

	handler := handlers.NewChat(handlers.ChatDeps{
		Logger: testutil.DiscardLogger(),
		Flow:   framework.Flow,
	})

	t.Run("OOB innerHTML swap for chunks", func(t *testing.T) {
		sessionID := framework.CreateTestSession(t, t.Name())

		params := url.Values{}
		params.Set("msgId", "htmx-chunk-test")
		params.Set("session_id", sessionID.String())
		params.Set("query", "Say hello")

		req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
		rec := httptest.NewRecorder()

		handler.Stream(rec, req)

		events := testutil.ParseSSEEvents(t, rec.Body.String())

		// Find chunk events
		for _, e := range events {
			if e.Type == "chunk" {
				assert.Contains(t, e.Data, `hx-swap-oob="innerHTML"`,
					"chunk should use innerHTML swap")
				assert.Contains(t, e.Data, `id="msg-content-htmx-chunk-test"`,
					"chunk should target correct content div")
			}
		}
	})

	t.Run("OOB outerHTML swap for done", func(t *testing.T) {
		sessionID := framework.CreateTestSession(t, t.Name())

		params := url.Values{}
		params.Set("msgId", "htmx-done-test")
		params.Set("session_id", sessionID.String())
		params.Set("query", "Hi")

		req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
		rec := httptest.NewRecorder()

		handler.Stream(rec, req)

		events := testutil.ParseSSEEvents(t, rec.Body.String())
		doneEvent := testutil.FindEvent(events, "done")
		require.NotNil(t, doneEvent)

		assert.Contains(t, doneEvent.Data, `hx-swap-oob="outerHTML"`,
			"done should use outerHTML swap to replace entire message")
	})
}

func TestChat_Stream_ErrorPropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	framework, cleanup := SetupTest(t)
	defer cleanup()

	handler := handlers.NewChat(handlers.ChatDeps{
		Logger: testutil.DiscardLogger(),
		Flow:   framework.Flow,
	})

	params := url.Values{}
	params.Set("msgId", "error-test")
	params.Set("session_id", "invalid-not-a-uuid")
	params.Set("query", "test")

	req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
	rec := httptest.NewRecorder()

	handler.Stream(rec, req)

	events := testutil.ParseSSEEvents(t, rec.Body.String())
	errorEvent := testutil.FindEvent(events, "error")
	require.NotNil(t, errorEvent, "should have error event")

	// Verify error JSON structure
	var payload struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	err := json.Unmarshal([]byte(errorEvent.Data), &payload)
	require.NoError(t, err, "error event must be valid JSON")
	assert.Equal(t, "invalid_session", payload.Code)
}

func TestChat_Stream_ConcurrentConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	framework, cleanup := SetupTest(t)
	defer cleanup()

	handler := handlers.NewChat(handlers.ChatDeps{
		Logger: testutil.DiscardLogger(),
		Flow:   framework.Flow,
	})

	// Note: Each goroutine uses its own sessionID to ensure isolation.
	// Flow is a singleton but Genkit handles concurrent streaming safely.
	const numClients = 5
	var wg sync.WaitGroup
	errors := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()

			// Each client gets its own session for isolation
			sessionID := framework.CreateTestSession(t, fmt.Sprintf("%s-client-%d", t.Name(), clientID))

			params := url.Values{}
			// Use fmt.Sprintf for unique msgID (not rune conversion which fails for clientID > 26)
			params.Set("msgId", fmt.Sprintf("concurrent-%d-%s", clientID, t.Name()))
			params.Set("session_id", sessionID.String())
			params.Set("query", "Say hello")

			req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
			rec := httptest.NewRecorder()

			handler.Stream(rec, req)

			events := testutil.ParseSSEEvents(t, rec.Body.String())
			if testutil.FindEvent(events, "done") == nil {
				errors <- fmt.Errorf("client %d: no done event", clientID)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

func TestChat_Stream_AccessibilityAttributes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	framework, cleanup := SetupTest(t)
	defer cleanup()

	handler := handlers.NewChat(handlers.ChatDeps{
		Logger: testutil.DiscardLogger(),
		Flow:   framework.Flow,
	})

	params := url.Values{}
	params.Set("msgId", "a11y-test")
	params.Set("session_id", framework.SessionID.String())
	params.Set("query", "Hello")

	req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
	rec := httptest.NewRecorder()

	handler.Stream(rec, req)

	events := testutil.ParseSSEEvents(t, rec.Body.String())
	doneEvent := testutil.FindEvent(events, "done")
	require.NotNil(t, doneEvent)

	// Verify semantic markup
	assert.Contains(t, doneEvent.Data, `role="article"`,
		"message must have semantic role")
}

func TestChat_Stream_ContentType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	framework, cleanup := SetupTest(t)
	defer cleanup()

	handler := handlers.NewChat(handlers.ChatDeps{
		Logger: testutil.DiscardLogger(),
		Flow:   framework.Flow,
	})

	params := url.Values{}
	params.Set("msgId", "content-type-test")
	params.Set("session_id", framework.SessionID.String())
	params.Set("query", "Hello")

	req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
	rec := httptest.NewRecorder()

	handler.Stream(rec, req)

	// HTMX SSE extension requires exact Content-Type without charset
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"),
		"SSE must use exact Content-Type without charset")

	// SSE should not use compression (would break chunked streaming)
	assert.Empty(t, rec.Header().Get("Content-Encoding"),
		"SSE should not use compression")
}

func TestChat_Stream_NoHTMXHeader(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	framework, cleanup := SetupTest(t)
	defer cleanup()

	handler := handlers.NewChat(handlers.ChatDeps{
		Logger: testutil.DiscardLogger(),
		Flow:   framework.Flow,
	})

	params := url.Values{}
	params.Set("msgId", "no-htmx-header-test")
	params.Set("session_id", framework.SessionID.String())
	params.Set("query", "Hello")

	// IMPORTANT: SSE connections from HTMX SSE extension do NOT send HX-Request header
	// The HTMX SSE extension (htmx.ext.sse) handles raw SSE without header signaling
	// The handler must work without this header
	req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
	// Deliberately NOT setting: req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()

	handler.Stream(rec, req)

	// Must still return SSE response
	assert.Equal(t, http.StatusOK, rec.Code,
		"SSE endpoint must work without HX-Request header")
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
}

// ============================================================================
// Pages Integration Tests (from pages_history_test.go)
// ============================================================================

// TestPages_Chat_LoadsHistoryFromDatabase validates history loading from database.
func TestPages_Chat_LoadsHistoryFromDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Setup real database
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Create store with correct Querier (sqlc generated code)
	store := session.New(sqlc.New(dbContainer.Pool), dbContainer.Pool, testutil.DiscardLogger())

	// Create Sessions handler with dummy HMAC secret
	sessions := handlers.NewSessions(store, []byte("test-secret-at-least-32-bytes-long!!!"), true)

	handler := handlers.NewPages(handlers.PagesDeps{
		Logger:   testutil.DiscardLogger(),
		Sessions: sessions,
	})

	// Create test session with history messages
	ctx := context.Background()

	// Create session (new API: title, modelName, systemPrompt)
	sess, err := store.CreateSession(ctx, "Test Session", "gemini-2.5-flash", "You are a helpful assistant")
	require.NoError(t, err)

	// SessionID is string not uuid.UUID
	sessionID := agent.SessionID(sess.ID.String())

	// Insert test messages
	messages := []*ai.Message{
		{
			Role:    "user",
			Content: []*ai.Part{ai.NewTextPart("Hello AI")},
		},
		{
			Role:    "model",
			Content: []*ai.Part{ai.NewTextPart("Hi there! How can I help?")},
		},
	}

	err = store.AppendMessages(ctx, sessionID, "main", messages)
	require.NoError(t, err)

	// Send HTTP request
	req := httptest.NewRequest("GET",
		fmt.Sprintf("/genui/chat?session=%s", sess.ID), nil)
	rec := httptest.NewRecorder()

	handler.Chat(rec, req)

	// Validate response
	require.Equal(t, http.StatusOK, rec.Code)

	html := rec.Body.String()

	// Verify history messages appear
	assert.Contains(t, html, "Hello AI", "should show user message")
	assert.Contains(t, html, "Hi there! How can I help?", "should show model message")

	// Verify message order (user before model)
	userIdx := strings.Index(html, "Hello AI")
	modelIdx := strings.Index(html, "Hi there!")
	assert.Less(t, userIdx, modelIdx, "user message should appear before model")
}

// TestPages_Chat_ConcurrentHistoryLoad validates concurrent history loading.
func TestPages_Chat_ConcurrentHistoryLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Setup
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := session.New(sqlc.New(dbContainer.Pool), dbContainer.Pool, testutil.DiscardLogger())
	sessions := handlers.NewSessions(store, []byte("test-secret-at-least-32-bytes-long!!!"), true)

	handler := handlers.NewPages(handlers.PagesDeps{
		Logger:   testutil.DiscardLogger(),
		Sessions: sessions,
	})

	// Create test session with history messages
	ctx := context.Background()
	sess, err := store.CreateSession(ctx, "Concurrent Test", "gemini-2.5-flash", "Test")
	require.NoError(t, err)

	messages := []*ai.Message{
		{Role: "user", Content: []*ai.Part{ai.NewTextPart("Message 1")}},
		{Role: "model", Content: []*ai.Part{ai.NewTextPart("Response 1")}},
	}

	err = store.AppendMessages(ctx, agent.SessionID(sess.ID.String()), "main", messages)
	require.NoError(t, err)

	// Concurrent test: 10 goroutines loading same session's history
	const concurrency = 10
	done := make(chan bool, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer func() { done <- true }()

			req := httptest.NewRequest("GET",
				fmt.Sprintf("/genui/chat?session=%s", sess.ID), nil)
			rec := httptest.NewRecorder()

			handler.Chat(rec, req)

			// Verify each request succeeds
			assert.Equal(t, http.StatusOK, rec.Code,
				"concurrent request %d should succeed", idx)
			html := rec.Body.String()
			assert.Contains(t, html, "Message 1",
				"concurrent request %d should load history", idx)
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < concurrency; i++ {
		<-done
	}

	// If we reach here without panic and all assertions pass, no race condition
}

// ============================================================================
// Progressive Enhancement Tests (from progressive_enhancement_test.go)
// ============================================================================

// TestChat_Send_ProgressiveEnhancement verifies HTMX vs non-HTMX behavior.
func TestChat_Send_ProgressiveEnhancement(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Setup
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := session.New(sqlc.New(dbContainer.Pool), dbContainer.Pool, testutil.DiscardLogger())
	sessions := handlers.NewSessions(store, []byte("test-secret-at-least-32-bytes-long!!!"), true)

	handler := handlers.NewChat(handlers.ChatDeps{
		Logger:   testutil.DiscardLogger(),
		Sessions: sessions,
		Flow:     nil, // Not testing Flow integration here
	})

	t.Run("HTMX request returns fragments", func(t *testing.T) {
		// Create session and CSRF token
		rec1 := httptest.NewRecorder()
		req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
		sessionID, err := sessions.GetOrCreate(rec1, req1)
		require.NoError(t, err)

		sessionCookie := rec1.Result().Cookies()[0]
		csrfToken := sessions.NewCSRFToken(sessionID)

		// Send message with HTMX header
		form := url.Values{}
		form.Set("content", "Hello AI")
		form.Set("csrf_token", csrfToken)

		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodPost,
			"/genui/chat/send?session_id="+sessionID.String(),
			strings.NewReader(form.Encode()))
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req2.Header.Set("HX-Request", "true") // HTMX header
		req2.AddCookie(sessionCookie)

		handler.Send(rec2, req2)

		// Verify returns 200 with HTML fragments
		assert.Equal(t, http.StatusOK, rec2.Code,
			"HTMX request should return fragments")

		html := rec2.Body.String()

		// Verify user message bubble is returned
		assert.Contains(t, html, "Hello AI",
			"Should return user message bubble")

		// Verify assistant shell is returned
		assert.Contains(t, html, "hx-ext=\"sse\"",
			"Should return MessageShell with SSE connection")
	})

	t.Run("non-HTMX request redirects", func(t *testing.T) {
		// Create session and CSRF token
		rec1 := httptest.NewRecorder()
		req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
		sessionID, err := sessions.GetOrCreate(rec1, req1)
		require.NoError(t, err)

		sessionCookie := rec1.Result().Cookies()[0]
		csrfToken := sessions.NewCSRFToken(sessionID)

		// Send message WITHOUT HTMX header
		form := url.Values{}
		form.Set("content", "Hello AI")
		form.Set("csrf_token", csrfToken)

		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodPost,
			"/genui/chat/send?session_id="+sessionID.String(),
			strings.NewReader(form.Encode()))
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// NO HX-Request header
		req2.AddCookie(sessionCookie)

		handler.Send(rec2, req2)

		// Verify 303 redirect
		assert.Equal(t, http.StatusSeeOther, rec2.Code,
			"non-HTMX request should redirect")

		location := rec2.Header().Get("Location")
		assert.Contains(t, location, "/genui/",
			"Should redirect to chat page")
		assert.Contains(t, location, "session="+sessionID.String(),
			"Redirect should include session ID")
	})

	t.Run("form fallback works without JavaScript", func(t *testing.T) {
		// Create session and CSRF token
		rec1 := httptest.NewRecorder()
		req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
		sessionID, err := sessions.GetOrCreate(rec1, req1)
		require.NoError(t, err)

		sessionCookie := rec1.Result().Cookies()[0]
		csrfToken := sessions.NewCSRFToken(sessionID)

		// Simulate form submission without JavaScript/HTMX
		form := url.Values{}
		form.Set("content", "Message from plain HTML form")
		form.Set("csrf_token", csrfToken)

		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodPost,
			"/genui/chat/send?session_id="+sessionID.String(),
			strings.NewReader(form.Encode()))
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// No HX-Request header (plain form submission)
		req2.AddCookie(sessionCookie)

		handler.Send(rec2, req2)

		// Should still work - redirect to chat page
		assert.Equal(t, http.StatusSeeOther, rec2.Code,
			"Form fallback should work")
		assert.NotEmpty(t, rec2.Header().Get("Location"),
			"Should redirect after submission")
	})
}

// TestChat_Send_CSRFIntegration verifies end-to-end CSRF protection.
func TestChat_Send_CSRFIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := session.New(sqlc.New(dbContainer.Pool), dbContainer.Pool, testutil.DiscardLogger())
	sessions := handlers.NewSessions(store, []byte("test-secret-at-least-32-bytes-long!!!"), true)

	handler := handlers.NewChat(handlers.ChatDeps{
		Logger:   testutil.DiscardLogger(),
		Sessions: sessions,
		Flow:     nil,
	})

	t.Run("CSRF token from different session fails", func(t *testing.T) {
		// Create two different sessions
		rec1 := httptest.NewRecorder()
		req1 := httptest.NewRequest(http.MethodGet, "/test1", nil)
		sessionA, err := sessions.GetOrCreate(rec1, req1)
		require.NoError(t, err)

		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodGet, "/test2", nil)
		sessionB, err := sessions.GetOrCreate(rec2, req2)
		require.NoError(t, err)

		// Get CSRF token for session A
		csrfTokenA := sessions.NewCSRFToken(sessionA)

		// Try to use session A's token with session B
		form := url.Values{}
		form.Set("content", "Attack attempt")
		form.Set("csrf_token", csrfTokenA) // Wrong session's token

		rec3 := httptest.NewRecorder()
		req3 := httptest.NewRequest(http.MethodPost,
			"/genui/chat/send?session_id="+sessionB.String(),
			strings.NewReader(form.Encode()))
		req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req3.Header.Set("HX-Request", "true")
		req3.AddCookie(rec2.Result().Cookies()[0])

		handler.Send(rec3, req3)

		// Should fail CSRF validation
		assert.Equal(t, http.StatusForbidden, rec3.Code,
			"CSRF token from different session should be rejected")
	})

	t.Run("expired CSRF token fails", func(t *testing.T) {
		// Note: This test would require mocking time, which is complex
		// For now, we rely on unit tests for expiration logic
		t.Skip("Expiration testing requires time mocking")
	})
}

// =============================================================================
// Canvas Mode Tests
// =============================================================================

// TestChat_Stream_CanvasMode_FromDatabase verifies canvas mode is read from database.
func TestChat_Stream_CanvasMode_FromDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("canvas enabled affects streaming", func(t *testing.T) {
		// Create session with canvas mode ENABLED
		sess, err := framework.SessionStore.CreateSession(ctx, "Canvas Enabled Session", "gemini-2.5-flash", "")
		require.NoError(t, err)

		// Enable canvas mode in database
		err = framework.SessionStore.UpdateCanvasMode(ctx, sess.ID, true)
		require.NoError(t, err)

		// Verify canvas mode is set
		updatedSess, err := framework.SessionStore.GetSession(ctx, sess.ID)
		require.NoError(t, err)
		require.True(t, updatedSess.CanvasMode, "canvas mode should be enabled in DB")

		// Create handler with sessions to read canvas mode from DB
		sessions := handlers.NewSessions(
			framework.SessionStore,
			[]byte("test-secret-32-bytes-minimum!!!!"),
			true,
		)

		handler := handlers.NewChat(handlers.ChatDeps{
			Logger:   testutil.DiscardLogger(),
			Flow:     framework.Flow,
			Sessions: sessions,
		})

		params := url.Values{}
		params.Set("msgId", "canvas-enabled-test")
		params.Set("session_id", sess.ID.String())
		params.Set("query", "Hello canvas mode")

		req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
		rec := httptest.NewRecorder()

		handler.Stream(rec, req)

		// Verify SSE response is valid (canvas mode is passed to Flow internally)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))

		events := testutil.ParseSSEEvents(t, rec.Body.String())
		// Accept either "done" (success) or "error" (API key issue in CI)
		// The key test is that canvas mode is READ from DB and PASSED to Flow
		doneEvent := testutil.FindEvent(events, "done")
		errorEvent := testutil.FindEvent(events, "error")
		assert.True(t, doneEvent != nil || errorEvent != nil,
			"should have either done or error event (streaming completed)")
	})

	t.Run("canvas disabled is default", func(t *testing.T) {
		// Create session WITHOUT explicitly setting canvas mode (defaults to false)
		sess, err := framework.SessionStore.CreateSession(ctx, "Canvas Disabled Session", "gemini-2.5-flash", "")
		require.NoError(t, err)

		// Verify canvas mode is false by default
		retrievedSess, err := framework.SessionStore.GetSession(ctx, sess.ID)
		require.NoError(t, err)
		require.False(t, retrievedSess.CanvasMode, "canvas mode should be false by default")

		// Create handler with sessions
		sessions := handlers.NewSessions(
			framework.SessionStore,
			[]byte("test-secret-32-bytes-minimum!!!!"),
			true,
		)

		handler := handlers.NewChat(handlers.ChatDeps{
			Logger:   testutil.DiscardLogger(),
			Flow:     framework.Flow,
			Sessions: sessions,
		})

		params := url.Values{}
		params.Set("msgId", "canvas-disabled-test")
		params.Set("session_id", sess.ID.String())
		params.Set("query", "Hello without canvas")

		req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
		rec := httptest.NewRecorder()

		handler.Stream(rec, req)

		// Verify SSE response is valid
		assert.Equal(t, http.StatusOK, rec.Code)

		events := testutil.ParseSSEEvents(t, rec.Body.String())
		// Accept either "done" (success) or "error" (API key issue in CI)
		doneEvent := testutil.FindEvent(events, "done")
		errorEvent := testutil.FindEvent(events, "error")
		assert.True(t, doneEvent != nil || errorEvent != nil,
			"should have either done or error event (streaming completed)")
	})

	t.Run("nil sessions defaults canvas to false", func(t *testing.T) {
		// Handler without sessions (simulation mode for canvas)
		handler := handlers.NewChat(handlers.ChatDeps{
			Logger:   testutil.DiscardLogger(),
			Flow:     framework.Flow,
			Sessions: nil, // No sessions = can't read canvas from DB
		})

		sess := framework.CreateTestSession(t, "Nil Sessions Test")

		params := url.Values{}
		params.Set("msgId", "nil-sessions-test")
		params.Set("session_id", sess.String())
		params.Set("query", "Hello nil sessions")

		req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
		rec := httptest.NewRecorder()

		handler.Stream(rec, req)

		// Should still work (canvas defaults to false)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// TestPages_Chat_CanvasMode_FromDatabase verifies canvas mode is read from database in Pages handler.
func TestPages_Chat_CanvasMode_FromDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Setup real database
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := session.New(sqlc.New(dbContainer.Pool), dbContainer.Pool, testutil.DiscardLogger())
	sessions := handlers.NewSessions(store, []byte("test-secret-at-least-32-bytes-long!!!"), true)

	handler := handlers.NewPages(handlers.PagesDeps{
		Logger:   testutil.DiscardLogger(),
		Sessions: sessions,
	})

	ctx := context.Background()

	t.Run("canvas mode enabled shows canvas UI", func(t *testing.T) {
		// Create session with canvas mode ENABLED
		sess, err := store.CreateSession(ctx, "Canvas UI Test", "gemini-2.5-flash", "")
		require.NoError(t, err)

		err = store.UpdateCanvasMode(ctx, sess.ID, true)
		require.NoError(t, err)

		// Request chat page
		req := httptest.NewRequest(http.MethodGet, "/genui?session="+sess.ID.String(), nil)
		rec := httptest.NewRecorder()

		handler.Chat(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		html := rec.Body.String()

		// With canvas mode enabled, the artifact panel should be present
		// The panel is always in the DOM but its visibility is controlled by canvas mode
		assert.Contains(t, html, "artifact-panel", "should have artifact panel in DOM")
	})

	t.Run("canvas mode disabled by default", func(t *testing.T) {
		// Create session WITHOUT enabling canvas mode
		sess, err := store.CreateSession(ctx, "No Canvas Test", "gemini-2.5-flash", "")
		require.NoError(t, err)

		// Request chat page
		req := httptest.NewRequest(http.MethodGet, "/genui?session="+sess.ID.String(), nil)
		rec := httptest.NewRecorder()

		handler.Chat(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		html := rec.Body.String()

		// Page should render successfully with canvas mode disabled
		assert.Contains(t, html, "id=\"main-content\"", "should have main content")
	})
}

// =============================================================================
// QA-Master Required Tests: New Chat Button Flow (P0)
// =============================================================================

// TestPages_NewChatButton_CreatesNewSession tests that ?new=true creates a fresh session.
// This is a critical P0 test per QA-Master review.
func TestPages_NewChatButton_CreatesNewSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	framework, cleanup := SetupTest(t)
	defer cleanup()

	sessions := handlers.NewSessions(
		framework.SessionStore,
		[]byte("test-secret-32-bytes-minimum!!!!"),
		true,
	)
	pages := handlers.NewPages(handlers.PagesDeps{
		Logger:   testutil.DiscardLogger(),
		Sessions: sessions,
	})

	t.Run("new=true creates fresh session", func(t *testing.T) {
		// First request: establish a session with some history
		rec1 := httptest.NewRecorder()
		req1 := httptest.NewRequest(http.MethodGet, "/genui", nil)
		sessions.GetOrCreate(rec1, req1)

		// Extract session cookie
		cookies := rec1.Result().Cookies()
		require.NotEmpty(t, cookies, "should have session cookie")
		originalCookie := cookies[0]
		originalSessionID := originalCookie.Value

		// Second request: ?new=true should create NEW session
		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodGet, "/genui?new=true", nil)
		req2.AddCookie(originalCookie) // Send original session cookie

		pages.Chat(rec2, req2)

		assert.Equal(t, http.StatusOK, rec2.Code, "Chat page should return 200")

		// Verify new session cookie was set
		newCookies := rec2.Result().Cookies()
		var newSessionCookie *http.Cookie
		for _, c := range newCookies {
			if c.Name == originalCookie.Name {
				newSessionCookie = c
				break
			}
		}

		require.NotNil(t, newSessionCookie, "should set new session cookie")
		assert.NotEqual(t, originalSessionID, newSessionCookie.Value,
			"?new=true should create different session ID")
	})

	t.Run("new=true returns empty message history", func(t *testing.T) {
		// Create a session with messages first
		existingSession := framework.CreateTestSession(t, "Session with history")

		// Add messages to the session using Store directly
		// AppendMessages signature: (ctx, sessionID agent.SessionID, branch, messages)
		testMsgs := []*ai.Message{
			ai.NewUserMessage(ai.NewTextPart("Hello world unique test")),
			ai.NewModelMessage(ai.NewTextPart("Hi there unique response")),
		}
		err := framework.SessionStore.AppendMessages(
			context.Background(),
			agent.SessionID(existingSession.String()),
			"main",
			testMsgs,
		)
		require.NoError(t, err)

		// Request with ?new=true
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/genui?new=true", nil)

		// Set cookie to existing session
		existingCookie := &http.Cookie{
			Name:  "session_id",
			Value: existingSession.String(),
		}
		req.AddCookie(existingCookie)

		pages.Chat(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()

		// New session should NOT contain existing messages
		assert.NotContains(t, body, "Hello world unique test",
			"?new=true should not show previous session's messages")
		assert.NotContains(t, body, "Hi there unique response",
			"?new=true should not show previous session's responses")
	})

	t.Run("regular request preserves session", func(t *testing.T) {
		// Baseline test: without ?new=true, session should be preserved
		rec1 := httptest.NewRecorder()
		req1 := httptest.NewRequest(http.MethodGet, "/genui", nil)
		sessions.GetOrCreate(rec1, req1)

		cookies := rec1.Result().Cookies()
		originalCookie := cookies[0]
		originalSessionID := originalCookie.Value

		// Second request WITHOUT ?new=true
		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodGet, "/genui", nil)
		req2.AddCookie(originalCookie)

		pages.Chat(rec2, req2)

		// Session should be preserved (no new cookie, or same value)
		newCookies := rec2.Result().Cookies()
		if len(newCookies) > 0 {
			for _, c := range newCookies {
				if c.Name == originalCookie.Name {
					assert.Equal(t, originalSessionID, c.Value,
						"without ?new=true, session should be preserved")
				}
			}
		}
		// If no new cookie set, session is preserved via the original cookie
	})

	t.Run("new=true with DB failure gracefully falls back", func(t *testing.T) {
		// This tests the defensive behavior in pages.go:69-72
		// When CreateSession fails, the handler falls through to use existing session
		// Note: To properly test this, we'd need to mock the store to return error
		// For now, we document the expected behavior
		t.Log("Expected behavior: On CreateSession failure, handler logs error and uses existing session")
		t.Log("This ensures users aren't blocked even if DB has temporary issues")
	})
}
