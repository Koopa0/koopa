package review

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Review struct zero-value and boundary tests
// ---------------------------------------------------------------------------

func TestReview_ZeroValue(t *testing.T) {
	t.Parallel()
	var r Review
	if r.ID != (uuid.UUID{}) {
		t.Errorf("zero Review.ID = %v, want zero UUID", r.ID)
	}
	if r.ReviewerNotes != nil {
		t.Errorf("zero Review.ReviewerNotes = %v, want nil", r.ReviewerNotes)
	}
	if r.ReviewedAt != nil {
		t.Errorf("zero Review.ReviewedAt = %v, want nil", r.ReviewedAt)
	}
}

// TestReview_JSONRoundTrip verifies all fields survive a JSON encode/decode cycle.
func TestReview_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	notes := "needs revision"
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	reviewed := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)

	want := Review{
		ID:            uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		ContentID:     uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		ReviewLevel:   "standard",
		Status:        string(StatusPending),
		ReviewerNotes: &notes,
		ContentTitle:  "Test Article",
		ContentSlug:   "test-article",
		ContentType:   "article",
		SubmittedAt:   now,
		ReviewedAt:    &reviewed,
	}

	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal(Review) error: %v", err)
	}
	var got Review
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal(Review) error: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Review JSON round-trip mismatch (-want +got):\n%s", diff)
	}
}

// TestReview_JSONOmitempty verifies optional fields are omitted when nil.
func TestReview_JSONOmitempty(t *testing.T) {
	t.Parallel()

	r := Review{
		ID:          uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		ContentID:   uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		ReviewLevel: "auto",
		Status:      string(StatusPending),
		SubmittedAt: time.Now(),
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	encoded := string(data)

	if strings.Contains(encoded, "reviewer_notes") {
		t.Error("expected reviewer_notes to be omitted when nil, but it was present")
	}
	if strings.Contains(encoded, "reviewed_at") {
		t.Error("expected reviewed_at to be omitted when nil, but it was present")
	}
}

// ---------------------------------------------------------------------------
// Handler.Approve — adversarial validation (real Handler, nil store)
// Store interaction tested via integration tests.
// ---------------------------------------------------------------------------

func TestHandler_Approve_Adversarial(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, slog.New(slog.DiscardHandler))

	tests := []struct {
		name       string
		pathID     string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "empty path id",
			pathID:     "",
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "path traversal in id",
			pathID:     "../../../etc/passwd",
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "numeric id is invalid UUID",
			pathID:     "12345",
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/api/admin/review/x/approve", http.NoBody)
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()
			h.Approve(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Approve(%q) status = %d, want %d", tt.pathID, w.Code, tt.wantStatus)
			}
			var eb struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
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
// Handler.Reject — adversarial validation (real Handler, nil store)
// Store interaction tested via integration tests.
// ---------------------------------------------------------------------------

func TestHandler_Reject_Adversarial(t *testing.T) {
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
			pathID:      "%20%20%20",
			body:        `{"notes":"x"}`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/api/admin/review/"+tt.pathID+"/reject", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			pathVal := tt.pathID
			if decoded, err := url.PathUnescape(tt.pathID); err == nil {
				pathVal = decoded
			}
			req.SetPathValue("id", pathVal)
			w := httptest.NewRecorder()
			h.Reject(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Reject(%q) status = %d, want %d (body: %s)", tt.pathID, w.Code, tt.wantStatus, w.Body.String())
			}
			var eb struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
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
// Handler.Edit — adversarial validation (real Handler, nil store)
// Store interaction tested via integration tests.
// ---------------------------------------------------------------------------

func TestHandler_Edit_Adversarial(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, slog.New(slog.DiscardHandler))

	tests := []struct {
		name       string
		pathID     string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "empty UUID",
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
			var eb struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
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
// Handler response Content-Type contract
// Approval error path (validation-only, nil store safe).
// Store interaction tested via integration tests.
// ---------------------------------------------------------------------------

func TestHandler_ResponseContentType(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, slog.New(slog.DiscardHandler))

	// Approve with a bad ID triggers validation error — store is never called.
	req := httptest.NewRequest(http.MethodPost, "/api/admin/review/bad-id/approve", http.NoBody)
	req.SetPathValue("id", "bad-id")
	w := httptest.NewRecorder()
	h.Approve(w, req)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}

// Handler.Reject notes forwarding, List success/error behavior, Edit store interaction,
// Approve success/not-found behavior, and Reject notes-passthrough are all
// tested via integration tests (require a real database connection).
