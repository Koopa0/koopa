package goal

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
)

// ---------------------------------------------------------------------------
// mapHTTPGoalStatus — pure business logic
// ---------------------------------------------------------------------------

func TestMapHTTPGoalStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    Status
		wantErr bool
	}{
		{name: "not_started canonical", input: "not_started", want: StatusNotStarted},
		{name: "Not Started display label", input: "Not Started", want: StatusNotStarted},
		{name: "Dream display label", input: "Dream", want: StatusNotStarted},
		{name: "in_progress canonical", input: "in_progress", want: StatusInProgress},
		{name: "In Progress display label", input: "In Progress", want: StatusInProgress},
		{name: "Active display label", input: "Active", want: StatusInProgress},
		{name: "done canonical", input: "done", want: StatusDone},
		{name: "Done display label", input: "Done", want: StatusDone},
		{name: "Achieved display label", input: "Achieved", want: StatusDone},
		{name: "abandoned canonical", input: "abandoned", want: StatusAbandoned},
		{name: "Abandoned display label", input: "Abandoned", want: StatusAbandoned},
		// adversarial
		{name: "empty string", input: "", wantErr: true},
		{name: "unknown status", input: "paused", wantErr: true},
		{name: "case mismatch not-Started", input: "not-Started", wantErr: true},
		{name: "extra whitespace", input: " done", wantErr: true},
		{name: "numeric string", input: "1", wantErr: true},
		{name: "SQL injection", input: "'; DROP TABLE goals; --", wantErr: true},
		{name: "XSS payload", input: "<script>alert(1)</script>", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := mapHTTPGoalStatus(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("mapHTTPGoalStatus(%q) = %q, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("mapHTTPGoalStatus(%q) unexpected error: %v", tt.input, err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mapHTTPGoalStatus(%q) mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.UpdateStatus — input validation (real Handler, nil store)
// ---------------------------------------------------------------------------

func TestUpdateStatus_Validation(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, nil, slog.New(slog.DiscardHandler))
	id := uuid.New().String()

	tests := []struct {
		name       string
		pathID     string
		body       string
		wantStatus int
		wantCode   string
	}{
		{name: "invalid UUID", pathID: "not-a-uuid", body: `{"status":"done"}`, wantStatus: 400, wantCode: "INVALID_ID"},
		{name: "empty UUID", pathID: "", body: `{"status":"done"}`, wantStatus: 400, wantCode: "INVALID_ID"},
		{name: "malformed JSON", pathID: id, body: `{bad}`, wantStatus: 400, wantCode: "INVALID_BODY"},
		{name: "empty body", pathID: id, body: ``, wantStatus: 400, wantCode: "INVALID_BODY"},
		{name: "missing status", pathID: id, body: `{"status":""}`, wantStatus: 400, wantCode: "MISSING_STATUS"},
		{name: "unknown status", pathID: id, body: `{"status":"paused"}`, wantStatus: 400, wantCode: "INVALID_STATUS"},
		{name: "SQL injection in status", pathID: id, body: `{"status":"';DROP TABLE--"}`, wantStatus: 400, wantCode: "INVALID_STATUS"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPut, "/api/admin/goals/"+tt.pathID+"/status", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()

			h.UpdateStatus(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("UpdateStatus(%q) status = %d, want %d (body: %s)", tt.name, w.Code, tt.wantStatus, w.Body.String())
			}
			var eb api.ErrorBody
			if err := json.NewDecoder(w.Body).Decode(&eb); err != nil {
				t.Fatalf("decoding error body: %v", err)
			}
			if eb.Error.Code != tt.wantCode {
				t.Errorf("UpdateStatus(%q) error.code = %q, want %q", tt.name, eb.Error.Code, tt.wantCode)
			}
		})
	}
}

// TestRegression_GoalStatusValidation verifies that the UpdateStatus handler
// rejects invalid/empty status with 400, rather than silently defaulting.
//
// Regression: before the fix, sending an empty or unknown status string was
// accepted without error, applying a silent default. Now it returns 400.
func TestRegression_GoalStatusValidation(t *testing.T) {
	t.Parallel()

	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	// Real Handler with nil store — validation rejects before store is called.
	h := NewHandler(nil, nil, slog.New(slog.DiscardHandler))

	tests := []struct {
		name     string
		body     map[string]string
		wantCode string
	}{
		{name: "empty status string", body: map[string]string{"status": ""}, wantCode: "MISSING_STATUS"},
		{name: "whitespace status", body: map[string]string{"status": " "}, wantCode: "INVALID_STATUS"},
		{name: "unknown status", body: map[string]string{"status": "maybe"}, wantCode: "INVALID_STATUS"},
		{name: "numeric status", body: map[string]string{"status": "123"}, wantCode: "INVALID_STATUS"},
		{name: "SQL injection", body: map[string]string{"status": "';DROP--"}, wantCode: "INVALID_STATUS"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bodyBytes, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatalf("marshaling body: %v", err)
			}
			req := httptest.NewRequest(http.MethodPut, "/api/admin/goals/"+id.String()+"/status",
				bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", id.String())
			w := httptest.NewRecorder()
			h.UpdateStatus(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("UpdateStatus(%q) status = %d, want 400", tt.name, w.Code)
			}
			var eb api.ErrorBody
			if err := json.NewDecoder(w.Body).Decode(&eb); err != nil {
				t.Fatalf("decoding error: %v", err)
			}
			if eb.Error.Code != tt.wantCode {
				t.Errorf("UpdateStatus(%q) error.code = %q, want %q", tt.name, eb.Error.Code, tt.wantCode)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.List — nil store panics (validation: none, store called immediately)
// Store interaction tests are in store_integration_test.go and server_test.go.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Handler.UpdateStatus success path — requires real store.
// Tested via server_test.go integration tests.
// ---------------------------------------------------------------------------
