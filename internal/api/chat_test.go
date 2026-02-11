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
	ctx := context.WithValue(r.Context(), ctxKeySessionID, sessionID)
	r = r.WithContext(ctx)

	newTestChatHandler().send(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("send() status = %d, want %d", w.Code, http.StatusOK)
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
	ctx := context.WithValue(r.Context(), ctxKeySessionID, sessionID)
	r = r.WithContext(ctx)

	newTestChatHandler().send(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("send() status = %d, want %d", w.Code, http.StatusOK)
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

func TestChatSend_SessionIDFromContext(t *testing.T) {
	sessionID := uuid.New()
	body, _ := json.Marshal(map[string]string{
		"content": "hello",
		// No sessionId in body
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	// Inject session ID via context (as sessionMiddleware would)
	ctx := context.WithValue(r.Context(), ctxKeySessionID, sessionID)
	r = r.WithContext(ctx)

	newTestChatHandler().send(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("send() status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]string
	decodeData(t, w, &resp)

	if resp["sessionId"] != sessionID.String() {
		t.Errorf("send() sessionId = %s, want %s (from context)", resp["sessionId"], sessionID)
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
	// Inject context session so we reach the body parse check
	ctx := context.WithValue(r.Context(), ctxKeySessionID, uuid.New())
	r = r.WithContext(ctx)

	newTestChatHandler().send(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("send(bad uuid) status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	errResp := decodeErrorEnvelope(t, w)

	if errResp.Code != "invalid_session" {
		t.Errorf("send(bad uuid) code = %q, want %q", errResp.Code, "invalid_session")
	}
}

func TestChatSend_NoSession(t *testing.T) {
	body, _ := json.Marshal(map[string]string{
		"content": "hello",
		// No sessionId in body, no session in context
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

func TestChatSend_InvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader([]byte("not json")))

	newTestChatHandler().send(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("send(invalid json) status = %d, want %d", w.Code, http.StatusBadRequest)
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
	ctx := context.WithValue(r.Context(), ctxKeySessionID, sessionID)
	r = r.WithContext(ctx)

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
	ctx := context.WithValue(r.Context(), ctxKeySessionID, sessionID)
	r = r.WithContext(ctx)

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
	ctx = context.WithValue(ctx, ctxKeySessionID, sessionID)

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

func TestChatSend_SessionMismatch(t *testing.T) {
	body, _ := json.Marshal(map[string]string{
		"content":   "hello",
		"sessionId": uuid.New().String(), // Different from context
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))
	ctx := context.WithValue(r.Context(), ctxKeySessionID, uuid.New())
	r = r.WithContext(ctx)

	newTestChatHandler().send(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("send(mismatched session) status = %d, want %d", w.Code, http.StatusForbidden)
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "forbidden" {
		t.Errorf("send(mismatched session) code = %q, want %q", errResp.Code, "forbidden")
	}
}

func TestStream_OwnershipDenied(t *testing.T) {
	ch := newTestChatHandler()
	sessionID := uuid.New()
	otherID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sessionID.String()+"&query=hi", nil)
	ctx := context.WithValue(r.Context(), ctxKeySessionID, otherID)
	r = r.WithContext(ctx)

	ch.stream(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("stream(wrong session) status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestStream_NoSession(t *testing.T) {
	ch := newTestChatHandler()
	sessionID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sessionID.String()+"&query=hi", nil)
	// No session in context

	ch.stream(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("stream(no session) status = %d, want %d", w.Code, http.StatusForbidden)
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
			}

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet,
				"/api/v1/chat/stream?msgId=m1&session_id="+sessionIDStr+"&query=test", nil)
			rctx := context.WithValue(r.Context(), ctxKeySessionID, sessionID)
			r = r.WithContext(rctx)

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
