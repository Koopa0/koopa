package session

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Koopa0/koopa0.dev/internal/api"
)

func newTestHandler() *Handler {
	return NewHandler(nil, slog.New(slog.DiscardHandler))
}

// ---------------------------------------------------------------------------
// List — query parameter validation (all paths before store call)
// ---------------------------------------------------------------------------

func TestList_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		query    string
		wantCode int
		wantErr  string
	}{
		// date validation
		{name: "invalid date format", query: "date=not-a-date", wantCode: 400, wantErr: "INVALID_DATE"},
		{name: "date with time", query: "date=2026-01-01T00:00:00Z", wantCode: 400, wantErr: "INVALID_DATE"},
		// date= (empty value) is treated as "no date param" → uses today's date → reaches store
		{name: "empty date uses today", query: "date=", wantCode: -1},
		{name: "SQL injection in date", query: "date=2026-01-01--DROP-TABLE", wantCode: 400, wantErr: "INVALID_DATE"},

		// days validation
		{name: "days zero", query: "days=0", wantCode: 400, wantErr: "INVALID_DAYS"},
		{name: "days negative", query: "days=-1", wantCode: 400, wantErr: "INVALID_DAYS"},
		{name: "days non-numeric", query: "days=abc", wantCode: 400, wantErr: "INVALID_DAYS"},
		{name: "days SQL injection", query: "days=1DROP-TABLE", wantCode: 400, wantErr: "INVALID_DAYS"},

		// type validation
		{name: "invalid type", query: "type=invalid", wantCode: 400, wantErr: "INVALID_TYPE"},
		{name: "XSS in type", query: "type=%3Cscript%3E", wantCode: 400, wantErr: "INVALID_TYPE"},
		{name: "SQL injection in type", query: "type=plan--DROP-TABLE", wantCode: 400, wantErr: "INVALID_TYPE"},
		// type= (empty) → q.Get("type") returns "" → skips type validation → reaches store
		{name: "empty type uses default", query: "type=", wantCode: -1},

		// valid types
		{name: "type plan valid", query: "type=plan", wantCode: -1}, // reaches store
		{name: "type reflection valid", query: "type=reflection", wantCode: -1},
		{name: "type context valid", query: "type=context", wantCode: -1},
		{name: "type metrics valid", query: "type=metrics", wantCode: -1},
		{name: "type insight valid", query: "type=insight", wantCode: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestHandler()
			req := httptest.NewRequest("GET", "/api/admin/session-notes?"+tt.query, http.NoBody)
			w := httptest.NewRecorder()

			func() {
				defer func() { recover() }() // nil store panic
				h.List(w, req)
			}()

			if tt.wantCode == -1 {
				// Expected to reach store (panic on nil) — validation passed
				return
			}

			if w.Code != tt.wantCode {
				t.Errorf("List(%q) status = %d, want %d", tt.query, w.Code, tt.wantCode)
			}
			if tt.wantErr != "" {
				var body api.ErrorBody
				if err := json.NewDecoder(w.Body).Decode(&body); err == nil {
					if body.Error.Code != tt.wantErr {
						t.Errorf("List(%q) error.code = %q, want %q", tt.query, body.Error.Code, tt.wantErr)
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// UpdateInsight — path parameter + body validation
// ---------------------------------------------------------------------------

func TestUpdateInsight_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pathID   string
		body     string
		wantCode int
	}{
		{name: "non-numeric id", pathID: "abc", body: `{"status":"verified"}`, wantCode: 400},
		{name: "empty id", pathID: "", body: `{"status":"verified"}`, wantCode: 400},
		{name: "SQL injection id", pathID: "1;DROP%20TABLE", body: `{"status":"verified"}`, wantCode: 400},
		{name: "malformed JSON body", pathID: "1", body: `{not json}`, wantCode: 400},
		{name: "empty body", pathID: "1", body: ``, wantCode: 400},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestHandler()
			req := httptest.NewRequest("PUT", "/api/admin/insights/"+tt.pathID, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()

			func() {
				defer func() { recover() }()
				h.UpdateInsight(w, req)
			}()

			if w.Code != tt.wantCode {
				t.Errorf("UpdateInsight(%q, %q) status = %d, want %d\nbody: %s",
					tt.pathID, tt.name, w.Code, tt.wantCode, w.Body.String())
			}
		})
	}
}
