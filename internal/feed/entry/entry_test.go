// Copyright 2026 Koopa. All rights reserved.

package entry

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// nullCollectedStatus (unexported helper)
// ---------------------------------------------------------------------------

func TestNullCollectedStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     *string
		wantValid bool
	}{
		{name: "nil input → invalid", input: nil, wantValid: false},
		{name: "non-nil string → valid", input: new("unread"), wantValid: true},
		{name: "empty string → valid (non-nil)", input: new(""), wantValid: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := nullCollectedStatus(tt.input)
			if got.Valid != tt.wantValid {
				t.Errorf("nullCollectedStatus(%v).Valid = %v, want %v", tt.input, got.Valid, tt.wantValid)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler: path UUID parsing (no real store needed)
// The handlers that parse path UUIDs return 400 before touching the store.
// We use a nil *Store; as long as the handler returns before calling the store,
// no panic occurs.
// ---------------------------------------------------------------------------

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &Handler{store: nil, logger: logger}
}

func TestHandler_Curate_InvalidUUID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		id   string
	}{
		{name: "empty id", id: ""},
		{name: "not a uuid", id: "not-a-uuid"},
		{name: "partial uuid", id: "12345678-1234-1234"},
		{name: "sql injection", id: "'; DROP TABLE collected_data; --"},
		{name: "unicode", id: "aaaa-bbbb-cccc-dddddddddddd-🙃"},
		{name: "too long", id: strings.Repeat("a", 256)},
	}

	h := newTestHandler(t)
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := strings.NewReader(`{"content_id":"` + uuid.New().String() + `"}`)
			req := httptest.NewRequest(http.MethodPost, "/api/admin/feed-entries/PLACEHOLDER/curate", body)
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()

			h.Curate(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Curate(%q) status = %d, want %d", tt.id, w.Code, http.StatusBadRequest)
			}
			assertErrorCode(t, w, "BAD_REQUEST")
		})
	}
}

func TestHandler_Ignore_InvalidUUID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		id   string
	}{
		{name: "empty id", id: ""},
		{name: "not a uuid", id: "abc"},
		{name: "integer", id: "42"},
		{name: "path traversal", id: "../../../etc/passwd"},
	}

	h := newTestHandler(t)
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()

			h.Ignore(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Ignore(%q) status = %d, want %d", tt.id, w.Code, http.StatusBadRequest)
			}
			assertErrorCode(t, w, "BAD_REQUEST")
		})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type errorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// assertErrorCode checks that the response body contains the expected error code.
func assertErrorCode(t *testing.T, w *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	var resp errorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding error response: %v (body: %s)", err, w.Body.String())
	}
	if resp.Error.Code != wantCode {
		t.Errorf("error code = %q, want %q", resp.Error.Code, wantCode)
	}
}
