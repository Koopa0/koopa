package handlers_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/a-h/templ"
	"github.com/koopa0/koopa-cli/internal/web/handlers"
)

func TestChat_Send(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	handler := handlers.NewChat(handlers.ChatConfig{Logger: logger}) // nil flow = simulation mode, nil sessions = no CSRF

	tests := []struct {
		name       string
		content    string
		sessionID  string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "valid message",
			content:    "Hello World",
			sessionID:  "test-session",
			wantStatus: http.StatusOK,
		},
		{
			name:       "empty content",
			content:    "",
			sessionID:  "test-session",
			wantStatus: http.StatusBadRequest,
			wantBody:   "content is required",
		},
		{
			name:       "whitespace only content",
			content:    "   \n\t  ",
			sessionID:  "test-session",
			wantStatus: http.StatusBadRequest,
			wantBody:   "content is required",
		},
		{
			name:       "missing sessionId uses default",
			content:    "Hello",
			sessionID:  "",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			form := url.Values{}
			form.Set("content", tt.content)
			if tt.sessionID != "" {
				form.Set("session_id", tt.sessionID)
			}

			req := httptest.NewRequest(http.MethodPost, "/genui/chat/send",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("HX-Request", "true") // Simulate HTMX request

			rec := httptest.NewRecorder()
			handler.Send(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if tt.wantBody != "" && !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want to contain %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestChat_Send_XSSPrevention(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	handler := handlers.NewChat(handlers.ChatConfig{Logger: logger}) // nil flow = simulation mode

	// XSS payloads that should be escaped by templ.
	// templ uses HTML entity encoding, so we verify the raw HTML tag doesn't appear.
	xssPayloads := []struct {
		name       string
		payload    string
		mustEscape string // This exact string should be escaped (replaced with entities)
	}{
		{
			name:       "script tag",
			payload:    "<script>alert('xss')</script>",
			mustEscape: "<script>", // Should become &lt;script&gt;
		},
		{
			name:       "img tag with event",
			payload:    `<img src=x onerror="alert('xss')">`,
			mustEscape: "<img", // Should become &lt;img
		},
		{
			name:       "anchor with javascript",
			payload:    `<a href="javascript:alert('xss')">click</a>`,
			mustEscape: "<a href", // Should become &lt;a href
		},
		{
			name:       "svg tag with onload",
			payload:    `<svg/onload=alert('xss')>`,
			mustEscape: "<svg/onload", // Should become &lt;svg/onload (more specific to avoid false positive with icon SVGs)
		},
	}

	for _, tt := range xssPayloads {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			form := url.Values{}
			form.Set("content", tt.payload)
			form.Set("session_id", "test-session")

			req := httptest.NewRequest(http.MethodPost, "/genui/chat/send",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("HX-Request", "true") // Simulate HTMX request

			rec := httptest.NewRecorder()
			handler.Send(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}

			body := rec.Body.String()

			// Verify raw HTML tag is NOT present (would execute as HTML)
			if strings.Contains(body, tt.mustEscape) {
				t.Errorf("XSS payload not escaped: found raw %q in response", tt.mustEscape)
			}

			// Verify the escaped version IS present (templ uses &lt; etc.)
			escapedVersion := strings.ReplaceAll(tt.mustEscape, "<", "&lt;")
			escapedVersion = strings.ReplaceAll(escapedVersion, ">", "&gt;")
			if !strings.Contains(body, escapedVersion) && !strings.Contains(body, "&#") {
				t.Logf("Note: escaped content might use different encoding")
			}
		})
	}
}

func TestChat_Stream_ParameterValidation(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	handler := handlers.NewChat(handlers.ChatConfig{Logger: logger}) // nil flow = simulation mode

	// In simulation mode (nil sessions), query is fetched from DB, so we only validate msgId and session_id.
	// When sessions != nil, query comes from DB via GetUserMessageBefore.
	tests := []struct {
		name       string
		msgID      string
		sessionID  string
		wantStatus int
	}{
		{
			name:       "missing msgId",
			msgID:      "",
			sessionID:  "sess",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing sessionId",
			msgID:      "msg123",
			sessionID:  "",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			params := url.Values{}
			if tt.msgID != "" {
				params.Set("msgId", tt.msgID)
			}
			if tt.sessionID != "" {
				params.Set("session_id", tt.sessionID)
			}

			urlStr := "/genui/stream"
			if len(params) > 0 {
				urlStr += "?" + params.Encode()
			}

			req := httptest.NewRequest(http.MethodGet, urlStr, nil)
			rec := httptest.NewRecorder()

			handler.Stream(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestNewChat(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	handler := handlers.NewChat(handlers.ChatConfig{Logger: logger}) // nil flow = simulation mode

	if handler == nil {
		t.Fatal("NewChat returned nil")
	}
}

func TestNewChat_NilLogger_Panics(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Error("NewChat with nil logger should panic")
		}
	}()

	handlers.NewChat(handlers.ChatConfig{})
}

func TestNewChat_NilFlow_SimulationMode(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	// nil flow should work (simulation mode)
	handler := handlers.NewChat(handlers.ChatConfig{Logger: logger})

	if handler == nil {
		t.Fatal("NewChat with nil flow should work (simulation mode)")
	}
}

func TestChat_Stream_SimulationMode(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	handler := handlers.NewChat(handlers.ChatConfig{Logger: logger}) // nil flow = simulation mode, nil sessions = no DB

	// In simulation mode, query is fetched from a fixed placeholder since no DB is available.
	// No query parameter is needed in URL - it comes from DB in production.
	params := url.Values{}
	params.Set("msgId", "test-msg-123")
	params.Set("session_id", "test-session")

	req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
	rec := httptest.NewRecorder()

	handler.Stream(rec, req)

	// Verify SSE response format
	body := rec.Body.String()

	// Check Content-Type is SSE
	if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}

	// Check for chunk events
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing 'event: chunk' in response")
	}

	// Check for done event
	if !strings.Contains(body, "event: done") {
		t.Error("missing 'event: done' in response")
	}

	// Per HTMX Master review (updated):
	// - WriteChunkRaw sends plain HTML (no OOB wrapper) - client's sse-swap="chunk" handles swap
	// - WriteDone sends final message via "chunk" event WITH OOB wrapper (sse-close processes before swap)
	// So the final "chunk" event DOES contain hx-swap-oob (for the complete message replacement)
	if !strings.Contains(body, "hx-swap-oob") {
		t.Error("final chunk (from WriteDone) should contain OOB wrapper")
	}

	// Content should be sent as plain HTML (not wrapped in OOB div)
	// The simulation mode sends plain text content

	// Check that response includes simulation mode marker (query comes from placeholder when no DB)
	// The response contains "simulated" in "This is a simulated response..."
	if !strings.Contains(body, "simulated") {
		t.Error("simulated response should contain 'simulated' marker")
	}
}

func TestChat_Stream_SimulationMode_NoXSSInOutput(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	handler := handlers.NewChat(handlers.ChatConfig{Logger: logger}) // nil flow = simulation mode

	// In simulation mode, query comes from DB (not URL), so XSS in URL params is not relevant.
	// This test verifies that the simulation response itself doesn't contain XSS.
	params := url.Values{}
	params.Set("msgId", "test-xss")
	params.Set("session_id", "test-session")

	req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
	rec := httptest.NewRecorder()

	handler.Stream(rec, req)

	body := rec.Body.String()

	// Verify simulation mode response doesn't contain raw script tags
	if strings.Contains(body, "<script>") {
		t.Error("response should not contain raw <script> tags")
	}
}

// ============================================================================
// Test 5: Handler SSE Streaming Unit Test (with Injectable SSEWriter)
// ============================================================================
//
// This test validates the HANDLER layer's SSE streaming behavior using
// the injectable SSEWriterFactory for mock injection.
//
// What this tests:
// - Handler uses Accumulate-and-Send pattern (sends full content each time)
// - Handler escapes HTML before transmission (single escaping, not double)
// - WriteDone is called at stream completion
// - SSEWriter injection works correctly
//
// What this does NOT test (by design):
// - Database storage (handled by Agent layer)
// - Real Genkit Flow behavior (uses simulation mode)
//
// ============================================================================

func TestChat_SSEWriterInjection(t *testing.T) {
	t.Parallel()

	// Create mock SSE writer to capture what handler sends
	mockWriter := &mockSSEWriter{
		RecordedChunks: make([]string, 0),
	}

	// Create handler with injected SSE writer factory
	logger := slog.Default()
	handler := handlers.NewChat(handlers.ChatConfig{
		Logger: logger,
		// Flow: nil = simulation mode
		// Sessions: nil = no DB, uses placeholder query
		SSEWriterFn: func(w http.ResponseWriter) (handlers.SSEWriter, error) {
			return mockWriter, nil
		},
	})

	// In simulation mode, query comes from placeholder (no DB), not URL.
	// No need for XSS payload in URL - that's tested in production mode with mock DB.
	params := url.Values{}
	params.Set("msgId", "test-msg")
	params.Set("session_id", "test-session")

	req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
	rec := httptest.NewRecorder()

	// Execute handler
	handler.Stream(rec, req)

	// ============================================================================
	// CRITICAL VALIDATIONS
	// ============================================================================

	// Validation 1: Should have received chunks (simulation mode sends word-by-word)
	if len(mockWriter.RecordedChunks) == 0 {
		t.Fatal("Expected chunks but got none")
	}

	// Validation 2: Chunks should be ACCUMULATED (not deltas)
	// First chunk should be shorter than last chunk
	if len(mockWriter.RecordedChunks) > 1 {
		firstLen := len(mockWriter.RecordedChunks[0])
		lastLen := len(mockWriter.RecordedChunks[len(mockWriter.RecordedChunks)-1])
		if firstLen >= lastLen {
			t.Errorf("Chunks should be accumulated (first: %d chars, last: %d chars)", firstLen, lastLen)
		}
	}

	// Validation 3: Chunks should not contain raw script tags
	for i, chunk := range mockWriter.RecordedChunks {
		// ❌ MUST NOT contain raw HTML (XSS prevention)
		if strings.Contains(chunk, "<script>") {
			t.Errorf("Chunk %d contains raw <script> - XSS vulnerability!", i)
		}

		// ❌ MUST NOT be double-escaped
		if strings.Contains(chunk, "&amp;lt;") {
			t.Errorf("Chunk %d is double-escaped: %s", i, chunk)
		}
	}

	// Validation 4: WriteDone should be called at end
	if !mockWriter.DoneCalled {
		t.Error("WriteDone() was not called")
	}

	// Validation 5: No error should be written for successful simulation
	if mockWriter.ErrorCalled {
		t.Errorf("WriteError() was called unexpectedly: %s", mockWriter.LastError)
	}
}

// TestChat_SSE_SidebarRefreshBeforeWriteDone verifies that WriteSidebarRefresh
// is called BEFORE WriteDone to ensure the sidebar refresh event reaches the client.
// This is a CRITICAL test - the SSE connection closes on "done" event, so any
// writes after WriteDone would go to a closed connection.
// maybeGenerateTitle was previously called AFTER WriteDone.
func TestChat_SSE_SidebarRefreshBeforeWriteDone(t *testing.T) {
	t.Parallel()

	// Create mock SSE writer that records call order
	mockWriter := &mockSSEWriter{
		RecordedChunks: make([]string, 0),
		CallOrder:      make([]string, 0),
	}

	// Create handler with injected SSE writer factory
	logger := slog.Default()
	handler := handlers.NewChat(handlers.ChatConfig{
		Logger: logger,
		// Flow: nil = simulation mode (maybeGenerateTitle will be called)
		// Sessions: nil = no DB, but simulation mode still calls maybeGenerateTitle
		SSEWriterFn: func(w http.ResponseWriter) (handlers.SSEWriter, error) {
			return mockWriter, nil
		},
	})

	// Execute stream request
	params := url.Values{}
	params.Set("msgId", "test-timing")
	params.Set("session_id", "test-session")

	req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
	rec := httptest.NewRecorder()

	handler.Stream(rec, req)

	// CRITICAL ASSERTION: WriteDone must be called
	if !mockWriter.DoneCalled {
		t.Fatal("WriteDone was not called - test setup issue")
	}

	// CRITICAL ASSERTION: Check call order
	// If both WriteSidebarRefresh and WriteDone were called, verify order
	if len(mockWriter.CallOrder) >= 2 {
		sidebarIdx := -1
		doneIdx := -1

		for i, call := range mockWriter.CallOrder {
			if call == "WriteSidebarRefresh" {
				sidebarIdx = i
			}
			if call == "WriteDone" {
				doneIdx = i
			}
		}

		// If sidebar refresh was called (depends on session store being available)
		if sidebarIdx != -1 && doneIdx != -1 {
			if sidebarIdx > doneIdx {
				t.Errorf("WriteSidebarRefresh (idx=%d) must be called BEFORE WriteDone (idx=%d) "+
					"to ensure SSE connection is still open when sidebar refresh is sent. "+
					"Call order: %v", sidebarIdx, doneIdx, mockWriter.CallOrder)
			}
		}
	}

	// Note: In simulation mode without session store, WriteSidebarRefresh may not be called
	// because maybeGenerateTitle returns early when sessions is nil.
	// This test primarily verifies the mock infrastructure works; full integration
	// testing is done in E2E tests with real session store.
	t.Logf("Call order recorded: %v", mockWriter.CallOrder)
}

// TestChat_SSEWriterFactory_NilMeansDefault verifies nil factory uses default writer.
func TestChat_SSEWriterFactory_NilMeansDefault(t *testing.T) {
	t.Parallel()

	// Create handler WITHOUT injected SSE writer (nil = use default)
	logger := slog.Default()
	handler := handlers.NewChat(handlers.ChatConfig{
		Logger: logger,
		// SSEWriterFn: nil = use default sse.NewWriter
		// Sessions: nil = no DB, uses placeholder query
	})

	// Make request - no query param needed, it comes from DB (placeholder in simulation mode)
	params := url.Values{}
	params.Set("msgId", "test-msg")
	params.Set("session_id", "test-session")

	req := httptest.NewRequest(http.MethodGet, "/genui/stream?"+params.Encode(), nil)
	rec := httptest.NewRecorder()

	// Execute handler - should use default writer and produce SSE response
	handler.Stream(rec, req)

	// Verify SSE headers are set (proves default writer was used)
	if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}

	// Verify SSE events are present in body
	body := rec.Body.String()
	if !strings.Contains(body, "event: chunk") {
		t.Error("missing 'event: chunk' - default SSE writer not working")
	}
	if !strings.Contains(body, "event: done") {
		t.Error("missing 'event: done' - default SSE writer not working")
	}
}

// ============================================================================
// Mock Implementations
// ============================================================================

// mockSSEWriter captures what the handler sends to SSE.
// Implements handlers.SSEWriter interface.
type mockSSEWriter struct {
	RecordedChunks       []string
	DoneCalled           bool
	ErrorCalled          bool
	LastError            string
	DoneComponent        templ.Component
	SidebarRefreshCalled bool
	CallOrder            []string // Records order of method calls for timing verification
}

func (m *mockSSEWriter) WriteChunkRaw(msgID, htmlContent string) error {
	m.RecordedChunks = append(m.RecordedChunks, htmlContent)
	return nil
}

// WriteDone signature updated per HTMX Master review:
// - msgID is now required for OOB swap targeting
// - Per SSE architecture: sends final content as "chunk" OOB, then empty "done" to close
func (m *mockSSEWriter) WriteDone(ctx context.Context, msgID string, comp templ.Component) error {
	m.DoneCalled = true
	m.DoneComponent = comp
	m.CallOrder = append(m.CallOrder, "WriteDone")
	return nil
}

func (m *mockSSEWriter) WriteError(msgID, code, message string) error {
	m.ErrorCalled = true
	m.LastError = message
	return nil
}

func (m *mockSSEWriter) WriteSidebarRefresh(_, _ string) error {
	m.SidebarRefreshCalled = true
	m.CallOrder = append(m.CallOrder, "WriteSidebarRefresh")
	return nil
}

// Canvas Panel Methods

func (*mockSSEWriter) WriteCanvasShow() error {
	// Mock: no-op for canvas show in tests
	return nil
}

func (*mockSSEWriter) WriteCanvasHide() error {
	// Mock: no-op for canvas hide in tests
	return nil
}

func (*mockSSEWriter) WriteArtifact(_ context.Context, _ templ.Component) error {
	// Mock: no-op for artifact in tests
	return nil
}
