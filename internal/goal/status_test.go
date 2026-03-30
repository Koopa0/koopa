package goal

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/api"
)

// TestRegression_GoalStatusValidation verifies that the UpdateStatus handler
// rejects invalid/empty status with 400, rather than silently defaulting.
//
// Regression: before the fix, sending an empty or unknown status string was
// accepted without error, applying a silent default. Now it returns 400.
func TestRegression_GoalStatusValidation(t *testing.T) {
	t.Parallel()

	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	// Real Handler with nil store — validation rejects before store is called.
	h := NewHandler(nil, slog.New(slog.DiscardHandler))

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
