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
	"testing"

	"github.com/google/uuid"
	"github.com/koopa0/koopa/internal/agent"
)

func newTestChatHandler() *chatHandler {
	return &chatHandler{
		logger: slog.New(slog.DiscardHandler),
	}
}

func TestChatSend_URLEncoding(t *testing.T) {
	ch := newTestChatHandler()

	sessionID := uuid.New()
	content := "你好 world & foo=bar#hash?query"

	body, _ := json.Marshal(map[string]string{
		"content":   content,
		"sessionId": sessionID.String(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	ch.send(w, r)

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
	ch := newTestChatHandler()

	sessionID := uuid.New()
	body, _ := json.Marshal(map[string]string{
		"content":   "hello",
		"sessionId": sessionID.String(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	ch.send(w, r)

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
	ch := newTestChatHandler()

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

	ch.send(w, r)

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
	ch := newTestChatHandler()

	body, _ := json.Marshal(map[string]string{
		"sessionId": uuid.New().String(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	ch.send(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("send(no content) status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	errResp := decodeErrorEnvelope(t, w)

	if errResp.Code != "content_required" {
		t.Errorf("send(no content) code = %q, want %q", errResp.Code, "content_required")
	}
}

func TestChatSend_EmptyContent(t *testing.T) {
	ch := newTestChatHandler()

	body, _ := json.Marshal(map[string]string{
		"content":   "   ",
		"sessionId": uuid.New().String(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	ch.send(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("send(whitespace) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestChatSend_InvalidSessionID(t *testing.T) {
	ch := newTestChatHandler()

	body, _ := json.Marshal(map[string]string{
		"content":   "hello",
		"sessionId": "not-a-uuid",
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	ch.send(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("send(bad uuid) status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	errResp := decodeErrorEnvelope(t, w)

	if errResp.Code != "invalid_session" {
		t.Errorf("send(bad uuid) code = %q, want %q", errResp.Code, "invalid_session")
	}
}

func TestChatSend_NoSession(t *testing.T) {
	ch := newTestChatHandler()

	body, _ := json.Marshal(map[string]string{
		"content": "hello",
		// No sessionId in body, no session in context
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))

	ch.send(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("send(no session) status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	errResp := decodeErrorEnvelope(t, w)

	if errResp.Code != "session_required" {
		t.Errorf("send(no session) code = %q, want %q", errResp.Code, "session_required")
	}
}

func TestChatSend_InvalidJSON(t *testing.T) {
	ch := newTestChatHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader([]byte("not json")))

	ch.send(w, r)

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
		{"short", "Hello world", 50, false},
		{"exact_50", "12345678901234567890123456789012345678901234567890", 50, false},
		{"long", "This is a very long message that exceeds the maximum allowed title length of fifty characters", 53, true},
		{"empty", "", 0, false},
		{"whitespace", "  hello  ", 50, false},
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

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{"invalid_session", agent.ErrInvalidSession, "invalid_session"},
		{"execution_failed", agent.ErrExecutionFailed, "execution_failed"},
		{"deadline_exceeded", context.DeadlineExceeded, "timeout"},
		{"generic_error", errors.New("something went wrong"), "flow_error"},
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
