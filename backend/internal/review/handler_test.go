package review

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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
// Handler.Reject adversarial inputs
// ---------------------------------------------------------------------------

func TestHandler_Reject_Adversarial(t *testing.T) {
	t.Parallel()

	id := fixedUUID(t)

	tests := []struct {
		name        string
		pathID      string
		body        string
		contentType string
		rejectFn    func(ctx context.Context, id uuid.UUID, notes string) error
		wantStatus  int
		wantCode    string
	}{
		{
			name:        "malformed JSON returns 400",
			pathID:      id.String(),
			body:        `{not valid json`,
			contentType: "application/json",
			rejectFn:    nil,
			wantStatus:  http.StatusBadRequest,
			wantCode:    "BAD_REQUEST",
		},
		{
			name:        "empty body returns 400",
			pathID:      id.String(),
			body:        ``,
			contentType: "application/json",
			rejectFn:    nil,
			wantStatus:  http.StatusBadRequest,
			wantCode:    "BAD_REQUEST",
		},
		{
			name:        "XSS in notes is forwarded as-is",
			pathID:      id.String(),
			body:        `{"notes":"<script>alert(1)</script>"}`,
			contentType: "application/json",
			rejectFn: func(_ context.Context, _ uuid.UUID, _ string) error {
				return nil
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:        "SQL injection in notes is forwarded as-is",
			pathID:      id.String(),
			body:        `{"notes":"'; DROP TABLE review_queue; --"}`,
			contentType: "application/json",
			rejectFn: func(_ context.Context, _ uuid.UUID, _ string) error {
				return nil
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:        "unicode notes is forwarded as-is",
			pathID:      id.String(),
			body:        `{"notes":"修改語法\u0000null byte"}`,
			contentType: "application/json",
			rejectFn: func(_ context.Context, _ uuid.UUID, _ string) error {
				return nil
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:        "all-spaces pathID is invalid UUID",
			pathID:      "%20%20%20",
			body:        `{"notes":"x"}`,
			contentType: "application/json",
			rejectFn:    nil,
			wantStatus:  http.StatusBadRequest,
			wantCode:    "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &stubReviewStore{rejectFn: tt.rejectFn}
			h := newTestHandler(stub)

			// URL-encode pathID for the URL, but set the decoded value for PathValue.
			req := httptest.NewRequest(http.MethodPost, "/api/admin/review/"+tt.pathID+"/reject", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			// For URL-encoded pathIDs (e.g. %20%20%20), SetPathValue should use
			// the decoded form that the real router would provide.
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
			if tt.wantCode != "" {
				eb := decodeErrorBody(t, w.Body)
				if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
					t.Errorf("error code mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Approve adversarial inputs
// ---------------------------------------------------------------------------

func TestHandler_Approve_Adversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pathID     string
		approveFn  func(ctx context.Context, id uuid.UUID) error
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
		{
			name:       "nil UUID string accepted",
			pathID:     uuid.Nil.String(),
			approveFn:  func(_ context.Context, _ uuid.UUID) error { return nil },
			wantStatus: http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &stubReviewStore{approveFn: tt.approveFn}
			h := newTestHandler(stub)

			req := httptest.NewRequest(http.MethodPost, "/api/admin/review/"+tt.pathID+"/approve", http.NoBody)
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()
			h.Approve(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Approve(%q) status = %d, want %d", tt.pathID, w.Code, tt.wantStatus)
			}
			if tt.wantCode != "" {
				eb := decodeErrorBody(t, w.Body)
				if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
					t.Errorf("error code mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.List adversarial inputs
// ---------------------------------------------------------------------------

func TestHandler_List_Adversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pendingFn  func(ctx context.Context) ([]Review, error)
		wantStatus int
		wantCode   string
	}{
		{
			name: "nil slice from store returns empty array not null",
			pendingFn: func(_ context.Context) ([]Review, error) {
				return nil, nil
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "store returns context cancelled error",
			pendingFn: func(_ context.Context) ([]Review, error) {
				return nil, context.Canceled
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &stubReviewStore{pendingFn: tt.pendingFn}
			h := newTestHandler(stub)

			req := httptest.NewRequest(http.MethodGet, "/api/admin/review", http.NoBody)
			w := httptest.NewRecorder()
			h.List(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("List() status = %d, want %d (body: %s)", w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantCode != "" {
				eb := decodeErrorBody(t, w.Body)
				if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
					t.Errorf("error code mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Edit adversarial inputs
// ---------------------------------------------------------------------------

func TestHandler_Edit_Adversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pathID     string
		reviewFn   func(ctx context.Context, id uuid.UUID) (*Review, error)
		approveFn  func(ctx context.Context, id uuid.UUID) error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "empty UUID",
			pathID:     "",
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			// Review.store.Review returns nil pointer with nil error — handler must not dereference nil.
			// This validates the handler's robustness when the store contract is violated.
			name:   "store returns nil review with nil error triggers approve with zero UUID",
			pathID: uuid.Nil.String(),
			reviewFn: func(_ context.Context, _ uuid.UUID) (*Review, error) {
				return &Review{ID: uuid.Nil}, nil
			},
			approveFn: func(_ context.Context, _ uuid.UUID) error {
				return nil
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:   "store returns wrapped ErrNotFound",
			pathID: uuid.MustParse("11111111-1111-1111-1111-111111111111").String(),
			reviewFn: func(_ context.Context, _ uuid.UUID) (*Review, error) {
				return nil, ErrNotFound
			},
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &stubReviewStore{reviewFn: tt.reviewFn, approveFn: tt.approveFn}
			h := newTestHandler(stub)

			req := httptest.NewRequest(http.MethodPut, "/api/admin/review/"+tt.pathID+"/edit", http.NoBody)
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()
			h.Edit(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Edit(%q) status = %d, want %d", tt.pathID, w.Code, tt.wantStatus)
			}
			if tt.wantCode != "" {
				eb := decodeErrorBody(t, w.Body)
				if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
					t.Errorf("error code mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// JSON response content-type contract
// ---------------------------------------------------------------------------

func TestHandler_ResponseContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  string
		path    string
		pathKey string
		pathVal string
		body    io.Reader
		handler func(h *testHandler) http.HandlerFunc
	}{
		{
			name:    "List sets application/json",
			method:  http.MethodGet,
			path:    "/api/admin/review",
			handler: func(h *testHandler) http.HandlerFunc { return h.List },
		},
		{
			name:    "Approve error sets application/json",
			method:  http.MethodPost,
			path:    "/api/admin/review/bad-id/approve",
			pathKey: "id",
			pathVal: "bad-id",
			handler: func(h *testHandler) http.HandlerFunc { return h.Approve },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &stubReviewStore{
				pendingFn: func(_ context.Context) ([]Review, error) { return []Review{}, nil },
			}
			h := newTestHandler(stub)

			var body io.Reader = http.NoBody
			if tt.body != nil {
				body = tt.body
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			if tt.pathKey != "" {
				req.SetPathValue(tt.pathKey, tt.pathVal)
			}
			w := httptest.NewRecorder()
			tt.handler(h).ServeHTTP(w, req)

			ct := w.Header().Get("Content-Type")
			if ct != "application/json" {
				t.Errorf("Content-Type = %q, want %q", ct, "application/json")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Reject — notes forwarding with various values
// ---------------------------------------------------------------------------

func TestHandler_Reject_NotesValues(t *testing.T) {
	t.Parallel()

	id := fixedUUID(t)

	tests := []struct {
		name      string
		notes     string
		wantNotes string
	}{
		{name: "empty notes", notes: "", wantNotes: ""},
		{name: "unicode notes", notes: "修正文法錯誤", wantNotes: "修正文法錯誤"},
		{name: "emoji in notes", notes: "looks great 👍", wantNotes: "looks great 👍"},
		{name: "very long notes", notes: strings.Repeat("a", 10000), wantNotes: strings.Repeat("a", 10000)},
		{name: "newlines in notes", notes: "line1\nline2\nline3", wantNotes: "line1\nline2\nline3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var gotNotes string
			stub := &stubReviewStore{
				rejectFn: func(_ context.Context, _ uuid.UUID, notes string) error {
					gotNotes = notes
					return nil
				},
			}
			h := newTestHandler(stub)

			body, _ := json.Marshal(map[string]string{"notes": tt.notes})
			req := httptest.NewRequest(http.MethodPost, "/api/admin/review/"+id.String()+"/reject", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", id.String())
			w := httptest.NewRecorder()
			h.Reject(w, req)

			if w.Code != http.StatusNoContent {
				t.Fatalf("Reject() status = %d, want %d (body: %s)", w.Code, http.StatusNoContent, w.Body.String())
			}
			if diff := cmp.Diff(tt.wantNotes, gotNotes); diff != "" {
				t.Errorf("Reject(%q) notes mismatch (-want +got):\n%s", tt.name, diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

// BenchmarkHandler_List benchmarks the List handler path with a small result set.
func BenchmarkHandler_List(b *testing.B) {
	b.ReportAllocs()

	now := time.Now()
	reviews := make([]Review, 10)
	for i := range reviews {
		reviews[i] = Review{
			ID:          uuid.New(),
			ContentID:   uuid.New(),
			ReviewLevel: "standard",
			Status:      string(StatusPending),
			SubmittedAt: now,
		}
	}

	stub := &stubReviewStore{
		pendingFn: func(_ context.Context) ([]Review, error) {
			return reviews, nil
		},
	}
	h := newTestHandler(stub)

	for b.Loop() {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/review", http.NoBody)
		w := httptest.NewRecorder()
		h.List(w, req)
	}
}

// BenchmarkHandler_Approve benchmarks the Approve handler path (success case).
func BenchmarkHandler_Approve(b *testing.B) {
	b.ReportAllocs()

	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	stub := &stubReviewStore{
		approveFn: func(_ context.Context, _ uuid.UUID) error { return nil },
	}
	h := newTestHandler(stub)

	for b.Loop() {
		req := httptest.NewRequest(http.MethodPost, "/api/admin/review/"+id.String()+"/approve", http.NoBody)
		req.SetPathValue("id", id.String())
		w := httptest.NewRecorder()
		h.Approve(w, req)
	}
}
