// Copyright 2026 Koopa. All rights reserved.

// White-box unit coverage for the reading package's boundary logic: the
// Status enum check, the two control-character validators (strict for
// single-line fields, prose-exempt for diary bodies), and the handler
// validation paths that must reject bad input with a 400 BEFORE any store
// or tx is touched. Validation-failure requests are served by a handler
// with a nil store on purpose — a missing boundary check would fall
// through to mustAdminTx and surface as a 500, failing the test cleanly.
//
// Control characters appear as \u escapes: Go source may not contain a
// raw NUL, and the JSON decoder unescapes \x00-style sequences inside
// the raw-string request bodies.
//
// DB-dependent behavior (defaults, auto-stamp, ordering, membership,
// cascade) lives in integration_test.go.

package reading

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatusValid(t *testing.T) {
	tests := []struct {
		name   string
		status Status
		want   bool
	}{
		{name: "want_to_read", status: StatusWantToRead, want: true},
		{name: "reading", status: StatusReading, want: true},
		{name: "finished", status: StatusFinished, want: true},
		{name: "abandoned", status: StatusAbandoned, want: true},
		{name: "empty", status: Status(""), want: false},
		{name: "unknown value", status: Status("paused"), want: false},
		{name: "case sensitive", status: Status("Finished"), want: false},
		{name: "content lifecycle value", status: Status("published"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.Valid(); got != tt.want {
				t.Errorf("Status(%q).Valid() = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestContainsControlChars(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "plain ascii", in: "The Three-Body Problem", want: false},
		{name: "cjk text", in: "呼吸 — 特德·姜", want: false},
		{name: "empty", in: "", want: false},
		{name: "null byte", in: "a\x00b", want: true},
		{name: "newline rejected in single-line fields", in: "line\nbreak", want: true},
		{name: "tab rejected in single-line fields", in: "a\tb", want: true},
		{name: "escape", in: "a\x1bb", want: true},
		{name: "del", in: "a\x7fb", want: true},
		{name: "c1 control", in: "a\u009fb", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsControlChars(tt.in); got != tt.want {
				t.Errorf("containsControlChars(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestContainsProseControlChars(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "plain prose", in: "Finished part one today.", want: false},
		{name: "newline allowed", in: "first line\nsecond line", want: false},
		{name: "tab allowed", in: "indent\tlist", want: false},
		{name: "carriage return allowed", in: "windows\r\nline", want: false},
		{name: "null byte", in: "a\x00b", want: true},
		{name: "escape", in: "a\x1bb", want: true},
		{name: "del", in: "a\x7fb", want: true},
		{name: "c1 control", in: "a\u0085b", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsProseControlChars(tt.in); got != tt.want {
				t.Errorf("containsProseControlChars(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// newValidationHandler returns a Handler whose store is nil: only requests
// that fail boundary validation may be served through it. A request that
// passes validation reaches mustAdminTx, finds no tx, and returns 500 —
// which is exactly how these tests detect a missing validation check.
func newValidationHandler() *Handler {
	return &Handler{logger: slog.New(slog.DiscardHandler)}
}

// errCode extracts error.code from an api.ErrorBody response.
func errCode(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decoding error body %s: %v", body, err)
	}
	return env.Error.Code
}

func TestCreateValidation(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantCode string
	}{
		{name: "missing title", body: `{}`, wantCode: "BAD_REQUEST"},
		{name: "blank title", body: `{"title":"   "}`, wantCode: "BAD_REQUEST"},
		{name: "control char in title", body: `{"title":"a\u0000b"}`, wantCode: "BAD_REQUEST"},
		{name: "control char in author", body: `{"title":"ok","author":"a\u001bb"}`, wantCode: "BAD_REQUEST"},
		{name: "invalid status", body: `{"title":"ok","status":"reading-now"}`, wantCode: "INVALID_STATUS"},
		{name: "malformed started_on", body: `{"title":"ok","started_on":"06/01/2026"}`, wantCode: "BAD_REQUEST"},
		{name: "malformed json", body: `{"title":`, wantCode: "BAD_REQUEST"},
	}
	h := newValidationHandler()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/admin/knowledge/readings", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.Create(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("Create(%s) status = %d, want %d", tt.body, w.Code, http.StatusBadRequest)
			}
			if got := errCode(t, w.Body.Bytes()); got != tt.wantCode {
				t.Errorf("Create(%s) error code = %q, want %q", tt.body, got, tt.wantCode)
			}
		})
	}
}

func TestUpdateValidation(t *testing.T) {
	const id = "0b5fbf45-9c4f-4aae-9777-6d616533a8e3"
	tests := []struct {
		name     string
		id       string
		body     string
		wantCode string
	}{
		{name: "invalid id", id: "not-a-uuid", body: `{}`, wantCode: "BAD_REQUEST"},
		{name: "blank title provided", id: id, body: `{"title":" "}`, wantCode: "BAD_REQUEST"},
		{name: "control char in title", id: id, body: `{"title":"a\u0000b"}`, wantCode: "BAD_REQUEST"},
		{name: "control char in author", id: id, body: `{"author":"a\u009fb"}`, wantCode: "BAD_REQUEST"},
		{name: "invalid status", id: id, body: `{"status":"done"}`, wantCode: "INVALID_STATUS"},
		{name: "malformed finished_on", id: id, body: `{"finished_on":"yesterday"}`, wantCode: "BAD_REQUEST"},
	}
	h := newValidationHandler()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/admin/knowledge/readings/"+tt.id, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()
			h.Update(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("Update(%s) status = %d, want %d", tt.body, w.Code, http.StatusBadRequest)
			}
			if got := errCode(t, w.Body.Bytes()); got != tt.wantCode {
				t.Errorf("Update(%s) error code = %q, want %q", tt.body, got, tt.wantCode)
			}
		})
	}
}

func TestCreateReflectionValidation(t *testing.T) {
	const id = "0b5fbf45-9c4f-4aae-9777-6d616533a8e3"
	tests := []struct {
		name string
		id   string
		body string
	}{
		{name: "invalid reading id", id: "nope", body: `{"body":"ok"}`},
		{name: "missing body", id: id, body: `{}`},
		{name: "blank body", id: id, body: `{"body":"  \n "}`},
		{name: "null byte in body", id: id, body: `{"body":"a\u0000b"}`},
		{name: "malformed entry_date", id: id, body: `{"body":"ok","entry_date":"June 1"}`},
	}
	h := newValidationHandler()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/admin/knowledge/readings/"+tt.id+"/reflections", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()
			h.CreateReflection(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("CreateReflection(%s) status = %d, want %d", tt.body, w.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestUpdateReflectionValidation(t *testing.T) {
	const (
		id  = "0b5fbf45-9c4f-4aae-9777-6d616533a8e3"
		rid = "31b1bd0e-6dbf-4287-b21f-1a4a4befa0c0"
	)
	tests := []struct {
		name string
		id   string
		rid  string
		body string
	}{
		{name: "invalid reading id", id: "x", rid: rid, body: `{}`},
		{name: "invalid reflection id", id: id, rid: "y", body: `{}`},
		{name: "blank body provided", id: id, rid: rid, body: `{"body":" "}`},
		{name: "escape char in body", id: id, rid: rid, body: `{"body":"a\u001bb"}`},
		{name: "malformed entry_date", id: id, rid: rid, body: `{"entry_date":"2026-6-1"}`},
	}
	h := newValidationHandler()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := "/api/admin/knowledge/readings/" + tt.id + "/reflections/" + tt.rid
			req := httptest.NewRequest(http.MethodPut, target, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.id)
			req.SetPathValue("rid", tt.rid)
			w := httptest.NewRecorder()
			h.UpdateReflection(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("UpdateReflection(%s) status = %d, want %d", tt.body, w.Code, http.StatusBadRequest)
			}
		})
	}
}
