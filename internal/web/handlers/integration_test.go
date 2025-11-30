//go:build integration

package handlers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

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
	params.Set("sessionId", framework.SessionID.String())
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
		params.Set("sessionId", sessionID.String())
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
		params.Set("sessionId", sessionID.String())
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
	params.Set("sessionId", "invalid-not-a-uuid")
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
			params.Set("sessionId", sessionID.String())
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
	params.Set("sessionId", framework.SessionID.String())
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
	params.Set("sessionId", framework.SessionID.String())
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
	params.Set("sessionId", framework.SessionID.String())
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
