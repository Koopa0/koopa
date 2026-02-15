package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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

func TestChatSend_URLEncoding(t *testing.T) {
	sessionID := uuid.New()
	content := "你好 world & foo=bar#hash?query"

	body, _ := json.Marshal(map[string]string{
		"content":   content,
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

	streamURL := resp["streamUrl"]
	if streamURL == "" {
		t.Fatal("send() expected streamUrl in response")
	}

	// Parse the URL and verify query parameter is properly encoded
	parsed, err := url.Parse(streamURL)
	if err != nil {
		t.Fatalf("streamUrl is not a valid URL: %v", err)
	}

	query := parsed.Query().Get("query")
	if query != content {
		t.Errorf("send() query = %q, want %q", query, content)
	}

	// Verify the raw URL doesn't contain unencoded special characters
	if bytes.ContainsAny([]byte(parsed.RawQuery), " #") {
		t.Errorf("send() raw query contains unencoded characters: %q", parsed.RawQuery)
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

func TestStream_QueryTooLong(t *testing.T) {
	ch := newTestChatHandler()
	sessionID := uuid.New()
	longQuery := strings.Repeat("x", maxChatContentLength+1)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sessionID.String()+"&query="+url.QueryEscape(longQuery), nil)

	ch.stream(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("stream(>32K query) status = %d, want %d\nbody: %s", w.Code, http.StatusRequestEntityTooLarge, w.Body.String())
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "content_too_long" {
		t.Errorf("stream(>32K query) code = %q, want %q", errResp.Code, "content_too_long")
	}
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
		name  string
		query string
	}{
		{name: "missing all", query: ""},
		{name: "missing session_id and query", query: "?msgId=abc"},
		{name: "missing msgId and query", query: "?session_id=abc"},
		{name: "missing query", query: "?msgId=abc&session_id=def"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream"+tt.query, nil)

			ch.stream(w, r)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("stream(%s) status = %d, want %d", tt.name, w.Code, http.StatusBadRequest)
			}

			errResp := decodeErrorEnvelope(t, w)
			if errResp.Code != "missing_params" {
				t.Errorf("stream(%s) code = %q, want %q", tt.name, errResp.Code, "missing_params")
			}
		})
	}
}

func TestStream_SSEHeaders(t *testing.T) {
	ch := newTestChatHandler() // flow is nil → error event (headers still set)
	sessionID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sessionID.String()+"&query=hi", nil)

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

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sessionID.String()+"&query=hello", nil)

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

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sessionID.String()+"&query=hi", nil)
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
	r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sessionID.String()+"&query=hi", nil)

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
	r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sessionID.String()+"&query=hi", nil)
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

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet,
				"/api/v1/chat/stream?msgId=m1&session_id="+sessionIDStr+"&query=test", nil)

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
