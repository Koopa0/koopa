package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"

	"github.com/koopa0/koopa/internal/chat"
)

func newTestChatHandler() *chatHandler {
	return &chatHandler{
		logger: slog.New(slog.DiscardHandler),
		// sessions is nil — ownership verification is skipped for unit tests
	}
}

// newTestChatHandlerWithSessions creates a chat handler with a session manager
// but no store, causing sessionAccessAllowed to always return false (ownership denied).
func newTestChatHandlerWithSessions() *chatHandler {
	return &chatHandler{
		logger:   slog.New(slog.DiscardHandler),
		sessions: &sessionManager{logger: slog.New(slog.DiscardHandler)},
	}
}

// storePendingQuery stores a query in the chatHandler's pending store for testing.
// This simulates what send() does before stream() is called.
func storePendingQuery(h *chatHandler, msgID, sessionID, query string) {
	h.pendingQueries.Store(msgID, pendingQuery{
		query:     query,
		sessionID: sessionID,
		createdAt: time.Now(),
	})
	h.pendingCount.Add(1)
}

func TestChatSend_PendingQueryStore(t *testing.T) {
	sessionID := uuid.New()
	content := "你好 world & foo=bar#hash?query"

	body, _ := json.Marshal(map[string]string{
		"content":   content,
		"sessionId": sessionID.String(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	ch := newTestChatHandler()
	ch.send(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("send() status = %d, want %d\nbody: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]string
	decodeData(t, w, &resp)

	streamURL := resp["streamUrl"]
	if streamURL == "" {
		t.Fatal("send() expected streamUrl in response")
	}

	// SECURITY: Verify query content is NOT in the URL (CWE-284).
	parsed, err := url.Parse(streamURL)
	if err != nil {
		t.Fatalf("streamUrl is not a valid URL: %v", err)
	}
	if parsed.Query().Get("query") != "" {
		t.Error("send() streamUrl should NOT contain query parameter (PII leakage risk)")
	}

	// Verify the query is stored server-side in pendingQueries.
	msgID := resp["msgId"]
	val, ok := ch.pendingQueries.Load(msgID)
	if !ok {
		t.Fatal("send() did not store pending query")
	}
	pq := val.(pendingQuery)
	if pq.query != content {
		t.Errorf("send() pending query = %q, want %q", pq.query, content)
	}
	if pq.sessionID != sessionID.String() {
		t.Errorf("send() pending sessionID = %q, want %q", pq.sessionID, sessionID.String())
	}
}

func TestChatSend_SessionIDFromBody(t *testing.T) {
	sessionID := uuid.New()
	body, _ := json.Marshal(map[string]string{
		"content":   "hello",
		"sessionId": sessionID.String(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	newTestChatHandler().send(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("send() status = %d, want %d\nbody: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]string
	decodeData(t, w, &resp)

	if resp["sessionId"] != sessionID.String() {
		t.Errorf("send() sessionId = %s, want %s", resp["sessionId"], sessionID)
	}

	if resp["msgId"] == "" {
		t.Error("send() expected non-empty msgId")
	}
}

func TestChatSend_MissingSessionID(t *testing.T) {
	body, _ := json.Marshal(map[string]string{
		"content": "hello",
		// No sessionId in body
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	newTestChatHandler().send(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("send(no session) status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "session_required" {
		t.Errorf("send(no session) code = %q, want %q", errResp.Code, "session_required")
	}
}

func TestChatSend_MissingContent(t *testing.T) {
	body, _ := json.Marshal(map[string]string{
		"sessionId": uuid.New().String(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	newTestChatHandler().send(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("send(no content) status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	errResp := decodeErrorEnvelope(t, w)

	if errResp.Code != "content_required" {
		t.Errorf("send(no content) code = %q, want %q", errResp.Code, "content_required")
	}
}

func TestChatSend_EmptyContent(t *testing.T) {
	body, _ := json.Marshal(map[string]string{
		"content":   "   ",
		"sessionId": uuid.New().String(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	newTestChatHandler().send(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("send(whitespace) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestChatSend_InvalidSessionID(t *testing.T) {
	body, _ := json.Marshal(map[string]string{
		"content":   "hello",
		"sessionId": "not-a-uuid",
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	newTestChatHandler().send(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("send(bad uuid) status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	errResp := decodeErrorEnvelope(t, w)

	if errResp.Code != "invalid_session" {
		t.Errorf("send(bad uuid) code = %q, want %q", errResp.Code, "invalid_session")
	}
}

func TestChatSend_InvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader([]byte("not json")))

	newTestChatHandler().send(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("send(invalid json) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestChatSend_BodyTooLarge(t *testing.T) {
	// Create a valid JSON body larger than maxRequestBodySize (1 MB).
	// The content field must be large enough so the whole JSON exceeds the limit.
	largeContent := strings.Repeat("x", maxRequestBodySize)
	body, _ := json.Marshal(map[string]string{
		"content":   largeContent,
		"sessionId": uuid.New().String(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	newTestChatHandler().send(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("send(>1MB body) status = %d, want %d\nbody: %s", w.Code, http.StatusRequestEntityTooLarge, w.Body.String())
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "body_too_large" {
		t.Errorf("send(>1MB body) code = %q, want %q", errResp.Code, "body_too_large")
	}
}

func TestChatSend_ContentTooLong(t *testing.T) {
	// Create content that exceeds maxChatContentLength (32K)
	longContent := strings.Repeat("x", maxChatContentLength+1)
	body, _ := json.Marshal(map[string]string{
		"content":   longContent,
		"sessionId": uuid.New().String(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	newTestChatHandler().send(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("send(>32K content) status = %d, want %d\nbody: %s", w.Code, http.StatusRequestEntityTooLarge, w.Body.String())
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "content_too_long" {
		t.Errorf("send(>32K content) code = %q, want %q", errResp.Code, "content_too_long")
	}
}

// TestLoadPendingQuery verifies the pending query store mechanics:
// one-time use (LoadAndDelete), TTL expiry, and session mismatch rejection.
func TestLoadPendingQuery(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		ch := newTestChatHandler()
		storePendingQuery(ch, "msg1", "sess1", "hello")

		query, ok := ch.loadPendingQuery("msg1", "sess1")
		if !ok {
			t.Fatal("loadPendingQuery() returned false, want true")
		}
		if query != "hello" {
			t.Errorf("loadPendingQuery() query = %q, want %q", query, "hello")
		}
	})

	t.Run("one-time use", func(t *testing.T) {
		t.Parallel()
		ch := newTestChatHandler()
		storePendingQuery(ch, "msg2", "sess2", "hello")

		// First load succeeds
		if _, ok := ch.loadPendingQuery("msg2", "sess2"); !ok {
			t.Fatal("loadPendingQuery() first call returned false")
		}
		// Second load fails (already consumed)
		if _, ok := ch.loadPendingQuery("msg2", "sess2"); ok {
			t.Error("loadPendingQuery() second call returned true, want false (one-time use)")
		}
	})

	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		ch := newTestChatHandler()

		if _, ok := ch.loadPendingQuery("nonexistent", "sess"); ok {
			t.Error("loadPendingQuery(nonexistent) returned true, want false")
		}
	})

	t.Run("session mismatch", func(t *testing.T) {
		t.Parallel()
		ch := newTestChatHandler()
		storePendingQuery(ch, "msg3", "sess-a", "hello")

		if _, ok := ch.loadPendingQuery("msg3", "sess-b"); ok {
			t.Error("loadPendingQuery(wrong session) returned true, want false")
		}
	})

	t.Run("expired", func(t *testing.T) {
		t.Parallel()
		ch := newTestChatHandler()
		// Store with a creation time beyond TTL
		ch.pendingQueries.Store("msg4", pendingQuery{
			query:     "old query",
			sessionID: "sess4",
			createdAt: time.Now().Add(-(pendingQueryTTL + time.Second)),
		})

		if _, ok := ch.loadPendingQuery("msg4", "sess4"); ok {
			t.Error("loadPendingQuery(expired) returned true, want false")
		}
	})
}

func TestChatSend_OwnershipDenied(t *testing.T) {
	body, _ := json.Marshal(map[string]string{
		"content":   "hello",
		"sessionId": uuid.New().String(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	// Use handler with sessions configured but no store — ownership always fails
	newTestChatHandlerWithSessions().send(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("send(ownership denied) status = %d, want %d", w.Code, http.StatusForbidden)
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "forbidden" {
		t.Errorf("send(ownership denied) code = %q, want %q", errResp.Code, "forbidden")
	}
}

func TestTruncateForTitle(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantMax  int
		wantDots bool
	}{
		{name: "short", input: "Hello world", wantMax: 50, wantDots: false},
		{name: "exact_50", input: "12345678901234567890123456789012345678901234567890", wantMax: 50, wantDots: false},
		{name: "long", input: "This is a very long message that exceeds the maximum allowed title length of fifty characters", wantMax: 53, wantDots: true},
		{name: "empty", input: "", wantMax: 0, wantDots: false},
		{name: "whitespace", input: "  hello  ", wantMax: 50, wantDots: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateForTitle(tt.input)
			runes := []rune(result)

			if len(runes) > tt.wantMax {
				t.Errorf("truncateForTitle(%q) length = %d runes, want max %d", tt.input, len(runes), tt.wantMax)
			}

			if tt.wantDots {
				if result[len(result)-3:] != "..." {
					t.Errorf("truncateForTitle(%q) = %q, want trailing '...'", tt.input, result)
				}
			}
		})
	}
}

func TestGetToolDisplay(t *testing.T) {
	// Known tool
	info := getToolDisplay("web_search")
	if info.StartMsg == "" {
		t.Error("getToolDisplay(web_search) StartMsg is empty")
	}
	if info.CompleteMsg == "" {
		t.Error("getToolDisplay(web_search) CompleteMsg is empty")
	}
	if info.ErrorMsg == "" {
		t.Error("getToolDisplay(web_search) ErrorMsg is empty")
	}

	// Unknown tool falls back to default
	def := getToolDisplay("unknown_tool")
	if def != defaultToolDisplay {
		t.Errorf("getToolDisplay(unknown) = %+v, want %+v", def, defaultToolDisplay)
	}
}

func TestStream_MissingParams(t *testing.T) {
	ch := newTestChatHandler()

	tests := []struct {
		name     string
		urlQuery string
		wantCode string
	}{
		{name: "missing all", urlQuery: "", wantCode: "missing_params"},
		{name: "missing session_id", urlQuery: "?msgId=abc", wantCode: "missing_params"},
		{name: "missing msgId", urlQuery: "?session_id=abc", wantCode: "missing_params"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream"+tt.urlQuery, nil)

			ch.stream(w, r)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("stream(%s) status = %d, want %d", tt.name, w.Code, http.StatusBadRequest)
			}

			errResp := decodeErrorEnvelope(t, w)
			if errResp.Code != tt.wantCode {
				t.Errorf("stream(%s) code = %q, want %q", tt.name, errResp.Code, tt.wantCode)
			}
		})
	}
}

func TestStream_NoPendingQuery(t *testing.T) {
	ch := newTestChatHandler()
	sessionID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet,
		"/api/v1/chat/stream?msgId=nonexistent&session_id="+sessionID.String(), nil)

	ch.stream(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("stream(no pending) status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "query_not_found" {
		t.Errorf("stream(no pending) code = %q, want %q", errResp.Code, "query_not_found")
	}
}

func TestStream_SSEHeaders(t *testing.T) {
	ch := newTestChatHandler() // flow is nil → error event (headers still set)
	sessionID := uuid.New()
	storePendingQuery(ch, "m1", sessionID.String(), "hi")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sessionID.String(), nil)

	ch.stream(w, r)

	wantHeaders := map[string]string{
		"Content-Type":      "text/event-stream",
		"Cache-Control":     "no-cache",
		"Connection":        "keep-alive",
		"X-Accel-Buffering": "no",
	}

	for header, want := range wantHeaders {
		if got := w.Header().Get(header); got != want {
			t.Errorf("stream() header %q = %q, want %q", header, got, want)
		}
	}
}

func TestStream_NilFlow(t *testing.T) {
	ch := newTestChatHandler() // flow is nil → error SSE event
	sessionID := uuid.New()
	storePendingQuery(ch, "m1", sessionID.String(), "hello")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sessionID.String(), nil)

	ch.stream(w, r)

	body := w.Body.String()

	// Should emit an error event, not chunk or done events
	if !strings.Contains(body, "event: error\n") {
		t.Error("stream(nil flow) expected error event in SSE output")
	}
	if !strings.Contains(body, "chat flow not initialized") {
		t.Error("stream(nil flow) expected 'chat flow not initialized' in error event")
	}
	if strings.Contains(body, "event: chunk\n") {
		t.Error("stream(nil flow) should not emit chunk events")
	}
	if strings.Contains(body, "event: done\n") {
		t.Error("stream(nil flow) should not emit done events")
	}
}

func TestSSEEvent_Format(t *testing.T) {
	w := httptest.NewRecorder()

	data := map[string]string{"msgId": "abc", "text": "hello"}
	err := sseEvent(w, "chunk", data)

	if err != nil {
		t.Fatalf("sseEvent() error: %v", err)
	}

	body := w.Body.String()

	// Verify SSE format: "event: <type>\ndata: <json>\n\n"
	if !strings.HasPrefix(body, "event: chunk\ndata: ") {
		t.Errorf("sseEvent() format = %q, want prefix %q", body, "event: chunk\ndata: ")
	}

	if !strings.HasSuffix(body, "\n\n") {
		t.Errorf("sseEvent() should end with double newline, got %q", body)
	}

	// Verify JSON payload is valid
	dataLine := strings.TrimPrefix(body, "event: chunk\ndata: ")
	dataLine = strings.TrimSuffix(dataLine, "\n\n")

	var decoded map[string]string
	if err := json.Unmarshal([]byte(dataLine), &decoded); err != nil {
		t.Fatalf("sseEvent() data is not valid JSON: %v", err)
	}

	if decoded["msgId"] != "abc" {
		t.Errorf("sseEvent() data.msgId = %q, want %q", decoded["msgId"], "abc")
	}
	if decoded["text"] != "hello" {
		t.Errorf("sseEvent() data.text = %q, want %q", decoded["text"], "hello")
	}
}

func TestSSEEvent_MarshalError(t *testing.T) {
	w := httptest.NewRecorder()

	// Channels cannot be marshaled to JSON
	err := sseEvent(w, "chunk", make(chan int))

	if err == nil {
		t.Fatal("sseEvent(unmarshalable) expected error, got nil")
	}
}

func TestStream_NilFlow_ContextCanceled(t *testing.T) {
	ch := newTestChatHandler() // flow is nil
	sessionID := uuid.New()
	storePendingQuery(ch, "m1", sessionID.String(), "hi")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sessionID.String(), nil)
	r = r.WithContext(ctx)

	ch.stream(w, r)

	body := w.Body.String()

	// Flow is nil, so error event is emitted regardless of context state.
	if !strings.Contains(body, "event: error\n") {
		t.Error("stream(nil flow, canceled) expected error event")
	}
	if strings.Contains(body, "event: done\n") {
		t.Error("stream(nil flow, canceled) should not emit done event")
	}
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{name: "invalid_session", err: chat.ErrInvalidSession, wantCode: "invalid_session"},
		{name: "execution_failed", err: chat.ErrExecutionFailed, wantCode: "execution_failed"},
		{name: "deadline_exceeded", err: context.DeadlineExceeded, wantCode: "timeout"},
		{name: "generic_error", err: errors.New("something went wrong"), wantCode: "flow_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, msg := classifyError(tt.err)
			if code != tt.wantCode {
				t.Errorf("classifyError() code = %q, want %q", code, tt.wantCode)
			}
			if msg == "" {
				t.Error("classifyError() message is empty")
			}
		})
	}
}

func TestStream_OwnershipDenied(t *testing.T) {
	// Handler with sessions configured but no store → ownership always fails
	ch := newTestChatHandlerWithSessions()
	sessionID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sessionID.String(), nil)

	ch.stream(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("stream(ownership denied) status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestStream_NoUser(t *testing.T) {
	// Handler with sessions configured but no user in context
	ch := newTestChatHandlerWithSessions()
	sessionID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sessionID.String(), nil)
	// No user in context

	ch.stream(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("stream(no user) status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// sseTestEvent represents a parsed SSE event for test assertions.
type sseTestEvent struct {
	Type string
	Data map[string]string
}

// parseSSEEvents parses an SSE response body into structured events.
func parseSSEEvents(t *testing.T, body string) []sseTestEvent {
	t.Helper()
	var events []sseTestEvent
	for _, block := range strings.Split(body, "\n\n") {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		var ev sseTestEvent
		for _, line := range strings.Split(block, "\n") {
			switch {
			case strings.HasPrefix(line, "event: "):
				ev.Type = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				raw := strings.TrimPrefix(line, "data: ")
				ev.Data = make(map[string]string)
				if err := json.Unmarshal([]byte(raw), &ev.Data); err != nil {
					t.Fatalf("parseSSEEvents: invalid JSON in data line %q: %v", raw, err)
				}
			}
		}
		if ev.Type != "" {
			events = append(events, ev)
		}
	}
	return events
}

// filterSSEEvents returns events matching the given type.
func filterSSEEvents(events []sseTestEvent, eventType string) []sseTestEvent {
	var filtered []sseTestEvent
	for _, e := range events {
		if e.Type == eventType {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// TestJSONToolEmitter verifies that jsonToolEmitter emits correct SSE events
// for tool start, complete, and error — for both known and unknown tools.
func TestJSONToolEmitter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		method    string // "start", "complete", "error"
		toolName  string
		wantEvent string
		wantMsg   string
	}{
		{
			name:      "start known tool",
			method:    "start",
			toolName:  "web_search",
			wantEvent: "tool_start",
			wantMsg:   toolDisplay["web_search"].StartMsg,
		},
		{
			name:      "start unknown tool",
			method:    "start",
			toolName:  "custom_tool",
			wantEvent: "tool_start",
			wantMsg:   defaultToolDisplay.StartMsg,
		},
		{
			name:      "complete known tool",
			method:    "complete",
			toolName:  "read_file",
			wantEvent: "tool_complete",
			wantMsg:   toolDisplay["read_file"].CompleteMsg,
		},
		{
			name:      "complete unknown tool",
			method:    "complete",
			toolName:  "custom_tool",
			wantEvent: "tool_complete",
			wantMsg:   defaultToolDisplay.CompleteMsg,
		},
		{
			name:      "error known tool",
			method:    "error",
			toolName:  "web_fetch",
			wantEvent: "tool_error",
			wantMsg:   toolDisplay["web_fetch"].ErrorMsg,
		},
		{
			name:      "error unknown tool",
			method:    "error",
			toolName:  "custom_tool",
			wantEvent: "tool_error",
			wantMsg:   defaultToolDisplay.ErrorMsg,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			emitter := &jsonToolEmitter{w: w, msgID: "test-msg"}

			switch tt.method {
			case "start":
				emitter.OnToolStart(tt.toolName)
			case "complete":
				emitter.OnToolComplete(tt.toolName)
			case "error":
				emitter.OnToolError(tt.toolName)
			}

			events := parseSSEEvents(t, w.Body.String())
			if len(events) != 1 {
				t.Fatalf("jsonToolEmitter.%s(%q) emitted %d events, want 1", tt.method, tt.toolName, len(events))
			}

			ev := events[0]
			if ev.Type != tt.wantEvent {
				t.Errorf("jsonToolEmitter.%s(%q) event type = %q, want %q", tt.method, tt.toolName, ev.Type, tt.wantEvent)
			}
			if ev.Data["msgId"] != "test-msg" {
				t.Errorf("jsonToolEmitter.%s(%q) msgId = %q, want %q", tt.method, tt.toolName, ev.Data["msgId"], "test-msg")
			}
			if ev.Data["tool"] != tt.toolName {
				t.Errorf("jsonToolEmitter.%s(%q) tool = %q, want %q", tt.method, tt.toolName, ev.Data["tool"], tt.toolName)
			}
			if ev.Data["message"] != tt.wantMsg {
				t.Errorf("jsonToolEmitter.%s(%q) message = %q, want %q", tt.method, tt.toolName, ev.Data["message"], tt.wantMsg)
			}
		})
	}
}

// TestCreateSession_MissingUser verifies that createSession returns 400
// when no user identity is present in the request context.
func TestCreateSession_MissingUser(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	// No user in context

	sm.createSession(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("createSession(no user) status = %d, want %d\nbody: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "user_required" {
		t.Errorf("createSession(no user) code = %q, want %q", errResp.Code, "user_required")
	}
}

// TestMaybeGenerateTitle_NilPaths verifies early-return paths in maybeGenerateTitle
// when sessions or store are nil, or when the session ID is invalid.
func TestMaybeGenerateTitle_NilPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		handler   *chatHandler
		sessionID string
	}{
		{
			name:      "nil sessions",
			handler:   &chatHandler{logger: slog.New(slog.DiscardHandler)},
			sessionID: uuid.New().String(),
		},
		{
			name: "nil store",
			handler: &chatHandler{
				logger:   slog.New(slog.DiscardHandler),
				sessions: &sessionManager{logger: slog.New(slog.DiscardHandler)},
			},
			sessionID: uuid.New().String(),
		},
		{
			name:      "invalid UUID",
			handler:   &chatHandler{logger: slog.New(slog.DiscardHandler)},
			sessionID: "not-a-uuid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			title := tt.handler.maybeGenerateTitle(context.Background(), tt.sessionID, "test message")
			if title != "" {
				t.Errorf("maybeGenerateTitle(%s) = %q, want empty string", tt.name, title)
			}
		})
	}
}

func TestStreamWithFlow(t *testing.T) {
	sessionID := uuid.New()
	sessionIDStr := sessionID.String()

	tests := []struct {
		name       string
		flowFn     func(context.Context, chat.Input, func(context.Context, chat.StreamChunk) error) (chat.Output, error)
		wantChunks []string          // expected chunk text values in order
		wantDone   map[string]string // expected fields in done event (nil = no done expected)
		wantError  map[string]string // expected fields in error event (nil = no error expected)
	}{
		{
			name: "success with chunks",
			flowFn: func(ctx context.Context, input chat.Input, stream func(context.Context, chat.StreamChunk) error) (chat.Output, error) {
				if stream != nil {
					if err := stream(ctx, chat.StreamChunk{Text: "Hello "}); err != nil {
						return chat.Output{}, err
					}
					if err := stream(ctx, chat.StreamChunk{Text: "World"}); err != nil {
						return chat.Output{}, err
					}
				}
				return chat.Output{Response: "Hello World", SessionID: input.SessionID}, nil
			},
			wantChunks: []string{"Hello ", "World"},
			wantDone:   map[string]string{"response": "Hello World", "sessionId": sessionIDStr},
		},
		{
			name: "flow error without chunks",
			flowFn: func(_ context.Context, _ chat.Input, _ func(context.Context, chat.StreamChunk) error) (chat.Output, error) {
				return chat.Output{}, chat.ErrInvalidSession
			},
			wantError: map[string]string{"code": "invalid_session"},
		},
		{
			name: "partial chunks then error",
			flowFn: func(ctx context.Context, _ chat.Input, stream func(context.Context, chat.StreamChunk) error) (chat.Output, error) {
				if stream != nil {
					if err := stream(ctx, chat.StreamChunk{Text: "partial"}); err != nil {
						return chat.Output{}, err
					}
				}
				return chat.Output{}, chat.ErrExecutionFailed
			},
			wantChunks: []string{"partial"},
			wantError:  map[string]string{"code": "execution_failed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			g := genkit.Init(ctx)
			flowName := "test/" + strings.ReplaceAll(tt.name, " ", "_")
			testFlow := genkit.DefineStreamingFlow(g, flowName, tt.flowFn)

			ch := &chatHandler{
				logger: slog.New(slog.DiscardHandler),
				flow:   testFlow,
				// sessions is nil — ownership skipped for unit tests
			}
			storePendingQuery(ch, "m1", sessionIDStr, "test")

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet,
				"/api/v1/chat/stream?msgId=m1&session_id="+sessionIDStr, nil)

			ch.stream(w, r)

			if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
				t.Fatalf("stream(%s) Content-Type = %q, want %q", tt.name, ct, "text/event-stream")
			}

			events := parseSSEEvents(t, w.Body.String())

			// Verify chunk events
			chunks := filterSSEEvents(events, "chunk")
			if len(chunks) != len(tt.wantChunks) {
				t.Fatalf("stream(%s) got %d chunk events, want %d", tt.name, len(chunks), len(tt.wantChunks))
			}
			for i, wantText := range tt.wantChunks {
				if got := chunks[i].Data["text"]; got != wantText {
					t.Errorf("stream(%s) chunk[%d].text = %q, want %q", tt.name, i, got, wantText)
				}
				if got := chunks[i].Data["msgId"]; got != "m1" {
					t.Errorf("stream(%s) chunk[%d].msgId = %q, want %q", tt.name, i, got, "m1")
				}
			}

			// Verify done event
			doneEvents := filterSSEEvents(events, "done")
			if tt.wantDone != nil {
				if len(doneEvents) != 1 {
					t.Fatalf("stream(%s) got %d done events, want 1", tt.name, len(doneEvents))
				}
				for k, want := range tt.wantDone {
					if got := doneEvents[0].Data[k]; got != want {
						t.Errorf("stream(%s) done.%s = %q, want %q", tt.name, k, got, want)
					}
				}
				if got := doneEvents[0].Data["msgId"]; got != "m1" {
					t.Errorf("stream(%s) done.msgId = %q, want %q", tt.name, got, "m1")
				}
			} else if len(doneEvents) != 0 {
				t.Errorf("stream(%s) got %d done events, want 0", tt.name, len(doneEvents))
			}

			// Verify error event
			errorEvents := filterSSEEvents(events, "error")
			if tt.wantError != nil {
				if len(errorEvents) != 1 {
					t.Fatalf("stream(%s) got %d error events, want 1", tt.name, len(errorEvents))
				}
				for k, want := range tt.wantError {
					if got := errorEvents[0].Data[k]; got != want {
						t.Errorf("stream(%s) error.%s = %q, want %q", tt.name, k, got, want)
					}
				}
			} else if len(errorEvents) != 0 {
				t.Errorf("stream(%s) got %d error events, want 0", tt.name, len(errorEvents))
			}
		})
	}
}

// TestChatSend_ConcurrentCapacity verifies that concurrent send() calls
// correctly enforce the capacity limit using the CAS loop (H1 fix).
// Under contention, the total entries stored must never exceed maxPendingQueries.
func TestChatSend_ConcurrentCapacity(t *testing.T) {
	t.Parallel()

	ch := newTestChatHandler()

	// Set count just below the limit, leaving room for exactly 5 more entries.
	const headroom = 5
	ch.pendingCount.Store(maxPendingQueries - headroom)

	// Launch more goroutines than headroom to create contention.
	const goroutines = 20
	results := make(chan int, goroutines) // collects HTTP status codes

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()

			body, _ := json.Marshal(map[string]string{
				"content":   "hello",
				"sessionId": uuid.New().String(),
			})

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))
			ch.send(w, r)
			results <- w.Code
		}()
	}
	wg.Wait()
	close(results)

	var ok, rejected int
	for code := range results {
		switch code {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			rejected++
		default:
			t.Errorf("unexpected status code: %d", code)
		}
	}

	// Exactly headroom requests should succeed; the rest must be rejected.
	if ok != headroom {
		t.Errorf("concurrent send(): %d succeeded, want exactly %d", ok, headroom)
	}
	if rejected != goroutines-headroom {
		t.Errorf("concurrent send(): %d rejected, want %d", rejected, goroutines-headroom)
	}

	// Counter must be at the capacity limit (not over).
	if got := ch.pendingCount.Load(); got != maxPendingQueries {
		t.Errorf("pendingCount after concurrent send = %d, want %d", got, maxPendingQueries)
	}
}

// TestCleanupAndConsumeRace verifies that when cleanExpiredPending and
// loadPendingQuery race on the same entry, the counter decrements exactly once (H2 fix).
// This ensures no counter drift from double-decrement.
func TestCleanupAndConsumeRace(t *testing.T) {
	t.Parallel()

	// Repeat multiple times to increase chance of triggering the race.
	for trial := range 50 {
		ch := newTestChatHandler()

		const n = 10
		// Store entries that are "just expired" — eligible for both cleanup and consume.
		for i := range n {
			msgID := fmt.Sprintf("msg-%d-%d", trial, i)
			ch.pendingQueries.Store(msgID, pendingQuery{
				query:     "test",
				sessionID: "sess",
				createdAt: time.Now().Add(-(pendingQueryTTL + time.Millisecond)),
			})
			ch.pendingCount.Add(1)
		}

		if got := ch.pendingCount.Load(); got != n {
			t.Fatalf("trial %d: initial pendingCount = %d, want %d", trial, got, n)
		}

		// Race: cleanup and consume goroutines run concurrently.
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			ch.cleanExpiredPending()
		}()

		go func() {
			defer wg.Done()
			for i := range n {
				msgID := fmt.Sprintf("msg-%d-%d", trial, i)
				ch.loadPendingQuery(msgID, "sess")
			}
		}()

		wg.Wait()

		// Counter must be exactly 0 — each entry decremented exactly once.
		if got := ch.pendingCount.Load(); got != 0 {
			t.Fatalf("trial %d: pendingCount after race = %d, want 0 (counter drift detected)", trial, got)
		}
	}
}

// TestChatSend_PendingCapacityLimit verifies that send() returns 429
// when the pending query count reaches maxPendingQueries (F6/CWE-400).
func TestChatSend_PendingCapacityLimit(t *testing.T) {
	t.Parallel()

	ch := newTestChatHandler()

	// Simulate capacity at the limit by setting the counter directly.
	ch.pendingCount.Store(maxPendingQueries)

	body, _ := json.Marshal(map[string]string{
		"content":   "hello",
		"sessionId": uuid.New().String(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	ch.send(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("send(at capacity) status = %d, want %d\nbody: %s", w.Code, http.StatusTooManyRequests, w.Body.String())
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "too_many_pending" {
		t.Errorf("send(at capacity) code = %q, want %q", errResp.Code, "too_many_pending")
	}
}

// TestChatSend_PendingCapacityBelowLimit verifies that send() succeeds
// when pending count is one below the limit.
func TestChatSend_PendingCapacityBelowLimit(t *testing.T) {
	t.Parallel()

	ch := newTestChatHandler()

	// One below the limit should succeed.
	ch.pendingCount.Store(maxPendingQueries - 1)

	body, _ := json.Marshal(map[string]string{
		"content":   "hello",
		"sessionId": uuid.New().String(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	ch.send(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("send(below capacity) status = %d, want %d\nbody: %s", w.Code, http.StatusOK, w.Body.String())
	}

	// Count should now be at the limit.
	if got := ch.pendingCount.Load(); got != maxPendingQueries {
		t.Errorf("pendingCount after send = %d, want %d", got, maxPendingQueries)
	}
}

// TestPendingCount_SendAndConsume verifies that pendingCount tracks
// store/load operations accurately.
func TestPendingCount_SendAndConsume(t *testing.T) {
	t.Parallel()

	ch := newTestChatHandler()

	if got := ch.pendingCount.Load(); got != 0 {
		t.Fatalf("initial pendingCount = %d, want 0", got)
	}

	// Store via helper (simulates send)
	storePendingQuery(ch, "msg1", "sess1", "hello")
	storePendingQuery(ch, "msg2", "sess2", "world")

	if got := ch.pendingCount.Load(); got != 2 {
		t.Fatalf("pendingCount after 2 stores = %d, want 2", got)
	}

	// Consume via loadPendingQuery (simulates stream)
	if _, ok := ch.loadPendingQuery("msg1", "sess1"); !ok {
		t.Fatal("loadPendingQuery(msg1) returned false")
	}

	if got := ch.pendingCount.Load(); got != 1 {
		t.Errorf("pendingCount after 1 consume = %d, want 1", got)
	}

	// Consume second
	if _, ok := ch.loadPendingQuery("msg2", "sess2"); !ok {
		t.Fatal("loadPendingQuery(msg2) returned false")
	}

	if got := ch.pendingCount.Load(); got != 0 {
		t.Errorf("pendingCount after 2 consumes = %d, want 0", got)
	}
}

// TestCleanExpiredPending verifies that cleanExpiredPending removes expired
// entries and decrements the counter correctly.
func TestCleanExpiredPending(t *testing.T) {
	t.Parallel()

	ch := newTestChatHandler()

	// Store 3 queries: 2 expired, 1 fresh
	ch.pendingQueries.Store("expired1", pendingQuery{
		query:     "old1",
		sessionID: "s1",
		createdAt: time.Now().Add(-(pendingQueryTTL + 10*time.Second)),
	})
	ch.pendingQueries.Store("expired2", pendingQuery{
		query:     "old2",
		sessionID: "s2",
		createdAt: time.Now().Add(-(pendingQueryTTL + 5*time.Second)),
	})
	ch.pendingQueries.Store("fresh1", pendingQuery{
		query:     "new1",
		sessionID: "s3",
		createdAt: time.Now(),
	})
	ch.pendingCount.Store(3)

	ch.cleanExpiredPending()

	// Only fresh1 should remain
	if got := ch.pendingCount.Load(); got != 1 {
		t.Errorf("pendingCount after cleanup = %d, want 1", got)
	}

	if _, ok := ch.pendingQueries.Load("expired1"); ok {
		t.Error("expired1 should have been cleaned")
	}
	if _, ok := ch.pendingQueries.Load("expired2"); ok {
		t.Error("expired2 should have been cleaned")
	}
	if _, ok := ch.pendingQueries.Load("fresh1"); !ok {
		t.Error("fresh1 should NOT have been cleaned")
	}
}

// TestCleanExpiredPending_InvalidType verifies that entries with unexpected
// types are cleaned up.
func TestCleanExpiredPending_InvalidType(t *testing.T) {
	t.Parallel()

	ch := newTestChatHandler()

	// Store an invalid type (not pendingQuery)
	ch.pendingQueries.Store("bad", "not a pendingQuery")
	ch.pendingCount.Store(1)

	ch.cleanExpiredPending()

	if got := ch.pendingCount.Load(); got != 0 {
		t.Errorf("pendingCount after cleanup = %d, want 0", got)
	}
	if _, ok := ch.pendingQueries.Load("bad"); ok {
		t.Error("invalid-type entry should have been cleaned")
	}
}

// TestStartPendingCleanup verifies that the background cleanup goroutine
// stops when the context is canceled.
func TestStartPendingCleanup(t *testing.T) {
	t.Parallel()

	ch := newTestChatHandler()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		ch.startPendingCleanup(ctx)
		close(done)
	}()

	// Cancel the context — goroutine should exit
	cancel()

	select {
	case <-done:
		// Goroutine exited cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("startPendingCleanup did not exit after context cancel")
	}
}
