package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"

	"github.com/koopa0/koopa/internal/chat"
)

// TestContract_ErrorEnvelope verifies that every known error path returns
// a response matching the contract: {"error": {"code": "...", "message": "..."}}.
// This catches any handler that bypasses WriteError and writes raw strings or
// non-envelope JSON, which would break frontend error handling.
func TestContract_ErrorEnvelope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		setup      func() (http.HandlerFunc, *http.Request) // returns handler + request
		wantStatus int
		wantCode   string
	}{
		// --- chat send() errors ---
		{
			name: "send/invalid_json",
			setup: func() (http.HandlerFunc, *http.Request) {
				ch := newTestChatHandler()
				r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader("{bad"))
				return ch.send, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_json",
		},
		{
			name: "send/content_required",
			setup: func() (http.HandlerFunc, *http.Request) {
				ch := newTestChatHandler()
				body, _ := json.Marshal(map[string]string{"content": "", "sessionId": uuid.New().String()})
				r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))
				return ch.send, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "content_required",
		},
		{
			name: "send/session_required",
			setup: func() (http.HandlerFunc, *http.Request) {
				ch := newTestChatHandler()
				body, _ := json.Marshal(map[string]string{"content": "hello"})
				r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))
				return ch.send, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "session_required",
		},
		{
			name: "send/invalid_session",
			setup: func() (http.HandlerFunc, *http.Request) {
				ch := newTestChatHandler()
				body, _ := json.Marshal(map[string]string{"content": "hello", "sessionId": "not-a-uuid"})
				r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))
				return ch.send, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_session",
		},
		{
			name: "send/content_too_long",
			setup: func() (http.HandlerFunc, *http.Request) {
				ch := newTestChatHandler()
				long := strings.Repeat("a", maxChatContentLength+1)
				body, _ := json.Marshal(map[string]string{"content": long, "sessionId": uuid.New().String()})
				r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))
				return ch.send, r
			},
			wantStatus: http.StatusRequestEntityTooLarge,
			wantCode:   "content_too_long",
		},
		{
			name: "send/forbidden",
			setup: func() (http.HandlerFunc, *http.Request) {
				ch := newTestChatHandlerWithSessions()
				body, _ := json.Marshal(map[string]string{"content": "hello", "sessionId": uuid.New().String()})
				r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))
				return ch.send, r
			},
			wantStatus: http.StatusForbidden,
			wantCode:   "forbidden",
		},
		{
			name: "send/too_many_pending",
			setup: func() (http.HandlerFunc, *http.Request) {
				ch := newTestChatHandler()
				ch.pendingCount.Store(maxPendingQueries)
				body, _ := json.Marshal(map[string]string{"content": "hello", "sessionId": uuid.New().String()})
				r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))
				return ch.send, r
			},
			wantStatus: http.StatusTooManyRequests,
			wantCode:   "too_many_pending",
		},
		// --- chat stream() errors ---
		{
			name: "stream/missing_params",
			setup: func() (http.HandlerFunc, *http.Request) {
				ch := newTestChatHandler()
				r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream", nil)
				return ch.stream, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "missing_params",
		},
		{
			name: "stream/invalid_session",
			setup: func() (http.HandlerFunc, *http.Request) {
				ch := newTestChatHandler()
				r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id=bad", nil)
				return ch.stream, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_session",
		},
		{
			name: "stream/forbidden",
			setup: func() (http.HandlerFunc, *http.Request) {
				ch := newTestChatHandlerWithSessions()
				sid := uuid.New().String()
				r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sid, nil)
				return ch.stream, r
			},
			wantStatus: http.StatusForbidden,
			wantCode:   "forbidden",
		},
		{
			name: "stream/query_not_found",
			setup: func() (http.HandlerFunc, *http.Request) {
				ch := newTestChatHandler()
				sid := uuid.New().String()
				r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=nonexistent&session_id="+sid, nil)
				return ch.stream, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "query_not_found",
		},
		// --- session handler errors ---
		{
			name: "createSession/user_required",
			setup: func() (http.HandlerFunc, *http.Request) {
				sm := newTestSessionManager()
				r := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
				return sm.createSession, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "user_required",
		},
		{
			name: "requireOwnership/missing_id",
			setup: func() (http.HandlerFunc, *http.Request) {
				sm := newTestSessionManager()
				r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/", nil)
				return func(w http.ResponseWriter, r *http.Request) {
					sm.requireOwnership(w, r)
				}, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "missing_id",
		},
		{
			name: "requireOwnership/invalid_id",
			setup: func() (http.HandlerFunc, *http.Request) {
				sm := newTestSessionManager()
				r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/not-uuid", nil)
				r.SetPathValue("id", "not-uuid")
				return func(w http.ResponseWriter, r *http.Request) {
					sm.requireOwnership(w, r)
				}, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_id",
		},
		{
			name: "requireOwnership/forbidden_no_user",
			setup: func() (http.HandlerFunc, *http.Request) {
				sm := newTestSessionManager()
				r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+uuid.New().String(), nil)
				r.SetPathValue("id", uuid.New().String())
				// No user in context
				return func(w http.ResponseWriter, r *http.Request) {
					sm.requireOwnership(w, r)
				}, r
			},
			wantStatus: http.StatusForbidden,
			wantCode:   "forbidden",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler, req := tt.setup()
			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d\nbody: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			// Contract: Content-Type must be application/json
			if ct := w.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want %q", ct, "application/json")
			}

			// Contract: body must be valid JSON with {"error": {"code": "...", "message": "..."}}
			var env struct {
				Error *Error `json:"error"`
				Data  any    `json:"data"`
			}
			if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
				t.Fatalf("response is not valid JSON: %v", err)
			}
			if env.Error == nil {
				t.Fatal("response missing \"error\" field — envelope contract violated")
			}
			if env.Error.Code == "" {
				t.Error("error.code is empty — must be a non-empty string")
			}
			if env.Error.Message == "" {
				t.Error("error.message is empty — must be a non-empty string")
			}
			if env.Error.Code != tt.wantCode {
				t.Errorf("error.code = %q, want %q", env.Error.Code, tt.wantCode)
			}
			if env.Error.Status != tt.wantStatus {
				t.Errorf("error.status = %d, want %d", env.Error.Status, tt.wantStatus)
			}
			if env.Data != nil {
				t.Errorf("error response has non-nil \"data\" field: %v", env.Data)
			}
		})
	}
}

// TestContract_SuccessEnvelope verifies that success responses wrap data
// in the {"data": <payload>} envelope format.
func TestContract_SuccessEnvelope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		setup      func() (http.HandlerFunc, *http.Request)
		wantStatus int
	}{
		{
			name: "send/success",
			setup: func() (http.HandlerFunc, *http.Request) {
				ch := newTestChatHandler()
				body, _ := json.Marshal(map[string]string{
					"content":   "hello",
					"sessionId": uuid.New().String(),
				})
				r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))
				return ch.send, r
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "csrfToken/pre-session",
			setup: func() (http.HandlerFunc, *http.Request) {
				sm := newTestSessionManager()
				r := httptest.NewRequest(http.MethodGet, "/api/v1/csrf-token", nil)
				return sm.csrfToken, r
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "csrfToken/user-bound",
			setup: func() (http.HandlerFunc, *http.Request) {
				sm := newTestSessionManager()
				r := httptest.NewRequest(http.MethodGet, "/api/v1/csrf-token", nil)
				ctx := context.WithValue(r.Context(), ctxKeyUserID, uuid.New().String())
				r = r.WithContext(ctx)
				return sm.csrfToken, r
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "listSessions/empty",
			setup: func() (http.HandlerFunc, *http.Request) {
				sm := newTestSessionManager()
				r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
				// No user → returns empty list
				return sm.listSessions, r
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler, req := tt.setup()
			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d\nbody: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			// Contract: Content-Type must be application/json
			if ct := w.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want %q", ct, "application/json")
			}

			// Contract: body must be valid JSON with a "data" field
			var env struct {
				Data  json.RawMessage `json:"data"`
				Error *Error          `json:"error"`
			}
			if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
				t.Fatalf("response is not valid JSON: %v", err)
			}
			if env.Data == nil {
				t.Fatal("success response missing \"data\" field — envelope contract violated")
			}
			if env.Error != nil {
				t.Errorf("success response has non-nil \"error\" field: %+v", env.Error)
			}
		})
	}
}

// TestContract_SSEEventSequence verifies the ordering contract for SSE events:
//   - chunk events precede the done event
//   - error terminates the stream (no done after error)
//   - tool events appear between chunks (not after done)
//   - every event has a valid JSON payload with msgId
func TestContract_SSEEventSequence(t *testing.T) {
	t.Parallel()

	sessionID := uuid.New()
	sessionIDStr := sessionID.String()

	tests := []struct {
		name      string
		flowFn    func(context.Context, chat.Input, func(context.Context, chat.StreamChunk) error) (chat.Output, error)
		wantOrder []string // expected event type sequence
	}{
		{
			name: "chunks then done",
			flowFn: func(ctx context.Context, input chat.Input, stream func(context.Context, chat.StreamChunk) error) (chat.Output, error) {
				if stream != nil {
					_ = stream(ctx, chat.StreamChunk{Text: "a"})
					_ = stream(ctx, chat.StreamChunk{Text: "b"})
				}
				return chat.Output{Response: "ab", SessionID: input.SessionID}, nil
			},
			wantOrder: []string{"chunk", "chunk", "done"},
		},
		{
			name: "error only",
			flowFn: func(_ context.Context, _ chat.Input, _ func(context.Context, chat.StreamChunk) error) (chat.Output, error) {
				return chat.Output{}, chat.ErrInvalidSession
			},
			wantOrder: []string{"error"},
		},
		{
			name: "chunks then error",
			flowFn: func(ctx context.Context, _ chat.Input, stream func(context.Context, chat.StreamChunk) error) (chat.Output, error) {
				if stream != nil {
					_ = stream(ctx, chat.StreamChunk{Text: "partial"})
				}
				return chat.Output{}, chat.ErrExecutionFailed
			},
			wantOrder: []string{"chunk", "error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			g := genkit.Init(ctx)
			flowName := "contract/" + strings.ReplaceAll(tt.name, " ", "_")
			testFlow := genkit.DefineStreamingFlow(g, flowName, tt.flowFn)

			ch := &chatHandler{
				logger: discardLogger(),
				flow:   testFlow,
			}
			storePendingQuery(ch, "m1", sessionIDStr, "test")

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=m1&session_id="+sessionIDStr, nil)

			ch.stream(w, r)

			events := parseSSEEvents(t, w.Body.String())

			// Contract: event sequence must match expected order
			got := make([]string, len(events))
			for i, ev := range events {
				got[i] = ev.Type
			}
			if len(got) != len(tt.wantOrder) {
				t.Fatalf("event count = %d, want %d\ngot:  %v\nwant: %v", len(got), len(tt.wantOrder), got, tt.wantOrder)
			}
			for i := range got {
				if got[i] != tt.wantOrder[i] {
					t.Errorf("event[%d] type = %q, want %q\nfull sequence: %v", i, got[i], tt.wantOrder[i], got)
				}
			}

			// Contract: every event must have a non-empty msgId in its data
			for i, ev := range events {
				if ev.Data["msgId"] == "" {
					t.Errorf("event[%d] (%s) missing msgId in data", i, ev.Type)
				}
			}

			// Contract: done event (if present) must be the last event
			for i, ev := range events {
				if ev.Type == "done" && i != len(events)-1 {
					t.Errorf("done event at index %d but total events = %d (must be last)", i, len(events))
				}
			}

			// Contract: error event (if present) must be the last event
			for i, ev := range events {
				if ev.Type == "error" && i != len(events)-1 {
					t.Errorf("error event at index %d but total events = %d (must be last)", i, len(events))
				}
			}

			// Contract: no events after done or error
			seenTerminal := false
			for _, ev := range events {
				if seenTerminal {
					t.Errorf("event %q found after terminal event (done/error)", ev.Type)
				}
				if ev.Type == "done" || ev.Type == "error" {
					seenTerminal = true
				}
			}
		})
	}
}

// TestContract_MemoryHandler_Errors verifies error envelope for memory API endpoints.
func TestContract_MemoryHandler_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		setup      func() (http.HandlerFunc, *http.Request)
		wantStatus int
		wantCode   string
	}{
		{
			name: "listMemories/forbidden_no_user",
			setup: func() (http.HandlerFunc, *http.Request) {
				mh := &memoryHandler{logger: discardLogger()}
				r := httptest.NewRequest(http.MethodGet, "/api/v1/memories", nil)
				// No user context
				return mh.listMemories, r
			},
			wantStatus: http.StatusForbidden,
			wantCode:   "forbidden",
		},
		{
			name: "getMemory/forbidden_no_user",
			setup: func() (http.HandlerFunc, *http.Request) {
				mh := &memoryHandler{logger: discardLogger()}
				r := httptest.NewRequest(http.MethodGet, "/api/v1/memories/"+uuid.New().String(), nil)
				r.SetPathValue("id", uuid.New().String())
				return mh.getMemory, r
			},
			wantStatus: http.StatusForbidden,
			wantCode:   "forbidden",
		},
		{
			name: "getMemory/invalid_id",
			setup: func() (http.HandlerFunc, *http.Request) {
				mh := &memoryHandler{logger: discardLogger()}
				r := httptest.NewRequest(http.MethodGet, "/api/v1/memories/not-a-uuid", nil)
				r.SetPathValue("id", "not-a-uuid")
				ctx := context.WithValue(r.Context(), ctxKeyUserID, "user1")
				r = r.WithContext(ctx)
				return mh.getMemory, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_id",
		},
		{
			name: "updateMemory/forbidden_no_user",
			setup: func() (http.HandlerFunc, *http.Request) {
				mh := &memoryHandler{logger: discardLogger()}
				r := httptest.NewRequest(http.MethodPatch, "/api/v1/memories/"+uuid.New().String(), nil)
				r.SetPathValue("id", uuid.New().String())
				return mh.updateMemory, r
			},
			wantStatus: http.StatusForbidden,
			wantCode:   "forbidden",
		},
		{
			name: "updateMemory/invalid_id",
			setup: func() (http.HandlerFunc, *http.Request) {
				mh := &memoryHandler{logger: discardLogger()}
				r := httptest.NewRequest(http.MethodPatch, "/api/v1/memories/not-a-uuid", nil)
				r.SetPathValue("id", "not-a-uuid")
				ctx := context.WithValue(r.Context(), ctxKeyUserID, "user1")
				r = r.WithContext(ctx)
				return mh.updateMemory, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_id",
		},
		{
			name: "updateMemory/invalid_body",
			setup: func() (http.HandlerFunc, *http.Request) {
				mh := &memoryHandler{logger: discardLogger()}
				r := httptest.NewRequest(http.MethodPatch, "/api/v1/memories/"+uuid.New().String(), strings.NewReader("{bad"))
				r.SetPathValue("id", uuid.New().String())
				ctx := context.WithValue(r.Context(), ctxKeyUserID, "user1")
				r = r.WithContext(ctx)
				return mh.updateMemory, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_body",
		},
		{
			name: "updateMemory/active_true_rejected",
			setup: func() (http.HandlerFunc, *http.Request) {
				mh := &memoryHandler{logger: discardLogger()}
				body, _ := json.Marshal(map[string]bool{"active": true})
				r := httptest.NewRequest(http.MethodPatch, "/api/v1/memories/"+uuid.New().String(), bytes.NewReader(body))
				r.SetPathValue("id", uuid.New().String())
				ctx := context.WithValue(r.Context(), ctxKeyUserID, "user1")
				r = r.WithContext(ctx)
				return mh.updateMemory, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_operation",
		},
		{
			name: "deleteMemory/forbidden_no_user",
			setup: func() (http.HandlerFunc, *http.Request) {
				mh := &memoryHandler{logger: discardLogger()}
				r := httptest.NewRequest(http.MethodDelete, "/api/v1/memories/"+uuid.New().String(), nil)
				r.SetPathValue("id", uuid.New().String())
				return mh.deleteMemory, r
			},
			wantStatus: http.StatusForbidden,
			wantCode:   "forbidden",
		},
		{
			name: "deleteMemory/invalid_id",
			setup: func() (http.HandlerFunc, *http.Request) {
				mh := &memoryHandler{logger: discardLogger()}
				r := httptest.NewRequest(http.MethodDelete, "/api/v1/memories/not-a-uuid", nil)
				r.SetPathValue("id", "not-a-uuid")
				ctx := context.WithValue(r.Context(), ctxKeyUserID, "user1")
				r = r.WithContext(ctx)
				return mh.deleteMemory, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler, req := tt.setup()
			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d\nbody: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			var env struct {
				Error *Error `json:"error"`
			}
			if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
				t.Fatalf("response is not valid JSON: %v", err)
			}
			if env.Error == nil {
				t.Fatal("response missing \"error\" field")
			}
			if env.Error.Code != tt.wantCode {
				t.Errorf("error.code = %q, want %q", env.Error.Code, tt.wantCode)
			}
		})
	}
}

// TestContract_SearchHandler_Errors verifies error envelope for search endpoint.
func TestContract_SearchHandler_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		setup      func() (http.HandlerFunc, *http.Request)
		wantStatus int
		wantCode   string
	}{
		{
			name: "search/forbidden_no_user",
			setup: func() (http.HandlerFunc, *http.Request) {
				sh := &searchHandler{logger: discardLogger()}
				r := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=test", nil)
				return sh.searchMessages, r
			},
			wantStatus: http.StatusForbidden,
			wantCode:   "forbidden",
		},
		{
			name: "search/missing_query",
			setup: func() (http.HandlerFunc, *http.Request) {
				sh := &searchHandler{logger: discardLogger()}
				r := httptest.NewRequest(http.MethodGet, "/api/v1/search", nil)
				ctx := context.WithValue(r.Context(), ctxKeyUserID, "user1")
				r = r.WithContext(ctx)
				return sh.searchMessages, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "missing_query",
		},
		{
			name: "search/query_too_long",
			setup: func() (http.HandlerFunc, *http.Request) {
				sh := &searchHandler{logger: discardLogger()}
				longQuery := strings.Repeat("x", 1001)
				r := httptest.NewRequest(http.MethodGet, "/api/v1/search?q="+longQuery, nil)
				ctx := context.WithValue(r.Context(), ctxKeyUserID, "user1")
				r = r.WithContext(ctx)
				return sh.searchMessages, r
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "query_too_long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler, req := tt.setup()
			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d\nbody: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			var env struct {
				Error *Error `json:"error"`
			}
			if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
				t.Fatalf("response is not valid JSON: %v", err)
			}
			if env.Error == nil {
				t.Fatal("response missing \"error\" field")
			}
			if env.Error.Code != tt.wantCode {
				t.Errorf("error.code = %q, want %q", env.Error.Code, tt.wantCode)
			}
		})
	}
}

// TestContract_StatsHandler_Errors verifies error envelope for stats endpoint.
func TestContract_StatsHandler_Errors(t *testing.T) {
	t.Parallel()

	sh := &statsHandler{logger: discardLogger()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	// No user context → forbidden

	sh.getStats(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("stats/forbidden status = %d, want %d\nbody: %s", w.Code, http.StatusForbidden, w.Body.String())
	}

	var env struct {
		Error *Error `json:"error"`
	}
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if env.Error == nil {
		t.Fatal("response missing \"error\" field")
	}
	if env.Error.Code != "forbidden" {
		t.Errorf("error.code = %q, want %q", env.Error.Code, "forbidden")
	}
}

// TestParseIntParam tests the query parameter parser used across handlers.
func TestParseIntParam(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		query      string
		key        string
		defaultVal int
		want       int
	}{
		{name: "missing param", query: "", key: "limit", defaultVal: 50, want: 50},
		{name: "valid value", query: "limit=20", key: "limit", defaultVal: 50, want: 20},
		{name: "zero value", query: "offset=0", key: "offset", defaultVal: 10, want: 0},
		{name: "negative value", query: "limit=-5", key: "limit", defaultVal: 50, want: 50},
		{name: "non-numeric", query: "limit=abc", key: "limit", defaultVal: 50, want: 50},
		{name: "empty value", query: "limit=", key: "limit", defaultVal: 50, want: 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, "/test?"+tt.query, nil)
			got := parseIntParam(r, tt.key, tt.defaultVal)
			if got != tt.want {
				t.Errorf("parseIntParam(r, %q, %d) = %d, want %d", tt.key, tt.defaultVal, got, tt.want)
			}
		})
	}
}

// TestContract_CSRFTokenLifecycle verifies the CSRF token provisioning flow:
//  1. Pre-session token: no uid cookie → get pre-session token → verify it
//  2. User-bound token: uid established → get user token → verify it
//  3. Cross-contamination: pre-session token must NOT pass user-bound check and vice versa
func TestContract_CSRFTokenLifecycle(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager()
	userID := uuid.New().String()

	// Phase 1: Pre-session token lifecycle
	t.Run("pre-session token lifecycle", func(t *testing.T) {
		t.Parallel()

		token := sm.NewPreSessionCSRFToken()
		if token == "" {
			t.Fatal("NewPreSessionCSRFToken() returned empty")
		}

		// Must have the "pre:" prefix
		if !isPreSessionToken(token) {
			t.Errorf("pre-session token %q does not start with %q", token, preSessionPrefix)
		}

		// Must pass pre-session check
		if err := sm.CheckPreSessionCSRF(token); err != nil {
			t.Fatalf("CheckPreSessionCSRF(valid) error: %v", err)
		}
	})

	// Phase 2: User-bound token lifecycle
	t.Run("user-bound token lifecycle", func(t *testing.T) {
		t.Parallel()

		token := sm.NewCSRFToken(userID)
		if token == "" {
			t.Fatal("NewCSRFToken() returned empty")
		}

		// Must NOT have the "pre:" prefix
		if isPreSessionToken(token) {
			t.Errorf("user-bound token %q should not start with %q", token, preSessionPrefix)
		}

		// Must pass user-bound check
		if err := sm.CheckCSRF(userID, token); err != nil {
			t.Fatalf("CheckCSRF(valid) error: %v", err)
		}
	})

	// Phase 3: Cross-contamination prevention
	t.Run("pre-session token rejected as user-bound", func(t *testing.T) {
		t.Parallel()

		preToken := sm.NewPreSessionCSRFToken()

		// Pre-session token used as user-bound → must fail
		if err := sm.CheckCSRF(userID, preToken); err == nil {
			t.Error("CheckCSRF(pre-session token) expected error, got nil")
		}
	})

	t.Run("user-bound token rejected as pre-session", func(t *testing.T) {
		t.Parallel()

		userToken := sm.NewCSRFToken(userID)

		// User-bound token used as pre-session → must fail
		if err := sm.CheckPreSessionCSRF(userToken); err == nil {
			t.Error("CheckPreSessionCSRF(user-bound token) expected error, got nil")
		}
	})
}

// TestContract_SecurityHeaders verifies that the full middleware stack
// sets required security headers on all responses.
func TestContract_SecurityHeaders(t *testing.T) {
	t.Parallel()

	srv, err := NewServer(context.Background(), ServerConfig{
		Logger:       discardLogger(),
		SessionStore: testStore(),
		CSRFSecret:   testCSRFSecret(),
		CORSOrigins:  []string{"http://localhost:4200"},
		IsDev:        false, // HSTS requires non-dev mode
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Test multiple endpoints to ensure headers are applied universally
	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/csrf-token"},
		{http.MethodGet, "/api/v1/sessions"},
	}

	requiredHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Content-Security-Policy":   "default-src 'none'",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			r := httptest.NewRequest(ep.method, ep.path, nil)
			srv.Handler().ServeHTTP(w, r)

			for header, want := range requiredHeaders {
				if got := w.Header().Get(header); got != want {
					t.Errorf("header %q = %q, want %q", header, got, want)
				}
			}
		})
	}
}
