package goal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// TestRegression_GoalStatusValidation verifies that an empty or unrecognized
// status string returns HTTP 400, not a silent default or a successful update
// with a zero-value status.
//
// Regression: the original handler had no status validation — an empty
// or unknown status string would fall through to the store with a zero-value
// Status, silently corrupting the goal record. The fix adds:
//   - empty status   → 400 MISSING_STATUS
//   - unknown status → 400 INVALID_STATUS
//
// If the fix were reverted (validation removed), empty status would reach
// UpdateStatus with status="" and this test would fail because it expects 400.
func TestRegression_GoalStatusValidation(t *testing.T) {
	t.Parallel()

	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tests := []struct {
		name       string
		body       map[string]string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "empty status must return 400 not silent default",
			body:       map[string]string{"status": ""},
			wantStatus: http.StatusBadRequest,
			wantCode:   "MISSING_STATUS",
		},
		{
			name:       "unknown status must return 400 not silent default",
			body:       map[string]string{"status": "pending"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_STATUS",
		},
		{
			name:       "whitespace-only status must return 400",
			body:       map[string]string{"status": "   "},
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_STATUS",
		},
		{
			name:       "numeric status must return 400",
			body:       map[string]string{"status": "1"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_STATUS",
		},
		{
			name:       "status with leading space must return 400",
			body:       map[string]string{"status": " done"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_STATUS",
		},
		{
			name:       "case-sensitive mismatch must return 400",
			body:       map[string]string{"status": "DONE"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_STATUS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// stubGoalStore is defined in goal_test.go (same package).
			// updateStatusFn must never be called — validation rejects before store.
			stub := &stubGoalStore{
				updateStatusFn: func(_ context.Context, _ uuid.UUID, _ Status) (*Goal, error) {
					t.Error("UpdateStatus was called despite invalid status — validation did not reject")
					return nil, nil
				},
			}
			h := newTestGoalHandler(stub)

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

			if w.Code != tt.wantStatus {
				t.Errorf("UpdateStatus(%q) status = %d, want %d",
					tt.body["status"], w.Code, tt.wantStatus)
			}
			if tt.wantCode != "" {
				var eb struct {
					Error struct {
						Code string `json:"code"`
					} `json:"error"`
				}
				if err := json.NewDecoder(w.Body).Decode(&eb); err != nil {
					t.Fatalf("decoding error body: %v", err)
				}
				if eb.Error.Code != tt.wantCode {
					t.Errorf("UpdateStatus(%q) error.code = %q, want %q",
						tt.body["status"], eb.Error.Code, tt.wantCode)
				}
			}
		})
	}
}
