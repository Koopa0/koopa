package review

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// ---------------------------------------------------------------------------
// Status constants
// ---------------------------------------------------------------------------

func TestStatusConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  Status
		want string
	}{
		{name: "pending", got: StatusPending, want: "pending"},
		{name: "approved", got: StatusApproved, want: "approved"},
		{name: "rejected", got: StatusRejected, want: "rejected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if string(tt.got) != tt.want {
				t.Errorf("Status%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Sentinel error identity
// ---------------------------------------------------------------------------

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "ErrNotFound wraps correctly", err: ErrNotFound, want: ErrNotFound},
		{name: "ErrConflict wraps correctly", err: ErrConflict, want: ErrConflict},
		{name: "wrapped ErrNotFound", err: errors.New("querying review: " + ErrNotFound.Error()), want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := errors.Is(tt.err, tt.want)
			if tt.want != nil && !got {
				t.Errorf("errors.Is(%v, %v) = false, want true", tt.err, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Approve — validation (real Handler, nil store)
// Store interaction tested via integration tests.
// ---------------------------------------------------------------------------

func TestHandler_Approve_Validation(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, slog.New(slog.DiscardHandler))

	tests := []struct {
		name       string
		pathID     string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "invalid uuid returns 400",
			pathID:     "not-a-uuid",
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/api/admin/review/"+tt.pathID+"/approve", http.NoBody)
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()
			h.Approve(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Approve(%q) status = %d, want %d", tt.pathID, w.Code, tt.wantStatus)
			}
			var eb api.ErrorBody
			if err := json.NewDecoder(w.Body).Decode(&eb); err != nil {
				t.Fatalf("decoding error body: %v", err)
			}
			if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
				t.Errorf("error code mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Reject — validation (real Handler, nil store)
// Store interaction tested via integration tests.
// ---------------------------------------------------------------------------

func TestHandler_Reject_Validation(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, slog.New(slog.DiscardHandler))

	tests := []struct {
		name        string
		pathID      string
		body        string
		contentType string
		wantStatus  int
		wantCode    string
	}{
		{
			name:        "invalid uuid returns 400",
			pathID:      "bad-id",
			body:        `{"notes":"x"}`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "BAD_REQUEST",
		},
		{
			name:        "malformed JSON returns 400",
			pathID:      uuid.MustParse("11111111-1111-1111-1111-111111111111").String(),
			body:        `{not valid json`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "BAD_REQUEST",
		},
		{
			name:        "empty body returns 400",
			pathID:      uuid.MustParse("11111111-1111-1111-1111-111111111111").String(),
			body:        ``,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "BAD_REQUEST",
		},
		{
			name:        "all-spaces pathID is invalid UUID",
			pathID:      "   ",
			body:        `{"notes":"x"}`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/api/admin/review/x/reject", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()
			h.Reject(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Reject(%q) status = %d, want %d (body: %s)", tt.pathID, w.Code, tt.wantStatus, w.Body.String())
			}
			var eb api.ErrorBody
			if err := json.NewDecoder(w.Body).Decode(&eb); err != nil {
				t.Fatalf("decoding error body: %v", err)
			}
			if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
				t.Errorf("error code mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Edit — validation (real Handler, nil store)
// Store interaction tested via integration tests.
// ---------------------------------------------------------------------------

func TestHandler_Edit_Validation(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, slog.New(slog.DiscardHandler))

	tests := []struct {
		name       string
		pathID     string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "invalid uuid returns 400",
			pathID:     "not-a-uuid",
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "empty UUID string returns 400",
			pathID:     "",
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPut, "/api/admin/review/x/edit", http.NoBody)
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()
			h.Edit(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Edit(%q) status = %d, want %d", tt.pathID, w.Code, tt.wantStatus)
			}
			var eb api.ErrorBody
			if err := json.NewDecoder(w.Body).Decode(&eb); err != nil {
				t.Fatalf("decoding error body: %v", err)
			}
			if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
				t.Errorf("error code mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
