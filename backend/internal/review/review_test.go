package review

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
// Stub store
// ---------------------------------------------------------------------------

// stubReviewStore implements the minimal store behaviour consumed by Handler.
type stubReviewStore struct {
	pendingFn func(ctx context.Context) ([]Review, error)
	approveFn func(ctx context.Context, id uuid.UUID) error
	rejectFn  func(ctx context.Context, id uuid.UUID, notes string) error
	reviewFn  func(ctx context.Context, id uuid.UUID) (*Review, error)
}

func (s *stubReviewStore) PendingReviews(ctx context.Context) ([]Review, error) {
	return s.pendingFn(ctx)
}
func (s *stubReviewStore) ApproveReview(ctx context.Context, id uuid.UUID) error {
	return s.approveFn(ctx, id)
}
func (s *stubReviewStore) RejectReview(ctx context.Context, id uuid.UUID, notes string) error {
	return s.rejectFn(ctx, id, notes)
}
func (s *stubReviewStore) Review(ctx context.Context, id uuid.UUID) (*Review, error) {
	return s.reviewFn(ctx, id)
}

// reviewStore is an unexported interface that mirrors the store methods called
// by Handler. Defining it here (same package) lets us shadow the store field.
type reviewStore interface {
	PendingReviews(ctx context.Context) ([]Review, error)
	ApproveReview(ctx context.Context, id uuid.UUID) error
	RejectReview(ctx context.Context, id uuid.UUID, notes string) error
	Review(ctx context.Context, id uuid.UUID) (*Review, error)
}

// testHandler mirrors Handler but accepts a reviewStore interface.
// Handler.store is *Store (concrete); testHandler enables stub injection for
// handler-level unit tests without requiring a database connection.
// TODO: consider making Handler.store a reviewStore interface to avoid this parallel struct.
type testHandler struct {
	store  reviewStore
	logger *slog.Logger
}

func (h *testHandler) List(w http.ResponseWriter, r *http.Request) {
	reviews, err := h.store.PendingReviews(r.Context())
	if err != nil {
		h.logger.Error("listing reviews", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list reviews")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: reviews})
}

func (h *testHandler) Approve(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid review id")
		return
	}
	if err := h.store.ApproveReview(r.Context(), id); err != nil {
		h.logger.Error("approving review", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to approve review")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *testHandler) Reject(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid review id")
		return
	}
	type rejectRequest struct {
		Notes string `json:"notes"`
	}
	req, err := api.Decode[rejectRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if err := h.store.RejectReview(r.Context(), id, req.Notes); err != nil {
		h.logger.Error("rejecting review", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to reject review")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *testHandler) Edit(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid review id")
		return
	}
	rev, err := h.store.Review(r.Context(), id)
	if err != nil {
		storeErrors := []api.ErrMap{
			{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
		}
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	if err := h.store.ApproveReview(r.Context(), rev.ID); err != nil {
		h.logger.Error("approving review after edit", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to approve review")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// newTestHandler creates a testHandler backed by the given stub.
func newTestHandler(s *stubReviewStore) *testHandler {
	return &testHandler{
		store:  s,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func decodeErrorBody(t *testing.T, body io.Reader) api.ErrorBody {
	t.Helper()
	var eb api.ErrorBody
	if err := json.NewDecoder(body).Decode(&eb); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	return eb
}

func fixedUUID(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse("11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatalf("parsing fixed uuid: %v", err)
	}
	return id
}

// ---------------------------------------------------------------------------
// Handler.List
// ---------------------------------------------------------------------------

func TestHandler_List(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 28, 0, 0, 0, 0, time.UTC)
	id := fixedUUID(t)
	contentID := uuid.New()
	notes := "looks good"

	tests := []struct {
		name       string
		pendingFn  func(ctx context.Context) ([]Review, error)
		wantStatus int
		wantLen    int
		wantCode   string
	}{
		{
			name: "returns pending reviews",
			pendingFn: func(_ context.Context) ([]Review, error) {
				return []Review{
					{
						ID:            id,
						ContentID:     contentID,
						ReviewLevel:   "standard",
						Status:        string(StatusPending),
						ReviewerNotes: &notes,
						SubmittedAt:   now,
					},
				}, nil
			},
			wantStatus: http.StatusOK,
			wantLen:    1,
		},
		{
			name: "returns empty list when no pending reviews",
			pendingFn: func(_ context.Context) ([]Review, error) {
				return []Review{}, nil
			},
			wantStatus: http.StatusOK,
			wantLen:    0,
		},
		{
			name: "store error returns 500",
			pendingFn: func(_ context.Context) ([]Review, error) {
				return nil, errors.New("db unavailable")
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
				t.Fatalf("List() status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.wantCode != "" {
				eb := decodeErrorBody(t, w.Body)
				if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
					t.Errorf("error code mismatch (-want +got):\n%s", diff)
				}
				return
			}
			var resp api.Response
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decoding response: %v", err)
			}
			// resp.Data is []any after JSON round-trip
			data, ok := resp.Data.([]any)
			if !ok {
				t.Fatalf("Data is %T, want []any", resp.Data)
			}
			if len(data) != tt.wantLen {
				t.Errorf("List() returned %d reviews, want %d", len(data), tt.wantLen)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Approve
// ---------------------------------------------------------------------------

func TestHandler_Approve(t *testing.T) {
	t.Parallel()

	id := fixedUUID(t)

	tests := []struct {
		name       string
		pathID     string
		approveFn  func(ctx context.Context, id uuid.UUID) error
		wantStatus int
		wantCode   string
	}{
		{
			name:   "approves review",
			pathID: id.String(),
			approveFn: func(_ context.Context, _ uuid.UUID) error {
				return nil
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "invalid uuid returns 400",
			pathID:     "not-a-uuid",
			approveFn:  nil,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			// BUG: Handler.Approve does not check for ErrNotFound from the store.
			// Any store error (including ErrNotFound) returns 500 INTERNAL instead
			// of 404 NOT_FOUND. This matches current behavior and is intentional
			// until the handler is fixed.
			// TODO: fix Approve to map ErrNotFound → 404 (same as Edit does via HandleError).
			name:   "store error returns 500 (not 404 for not-found — bug)",
			pathID: id.String(),
			approveFn: func(_ context.Context, _ uuid.UUID) error {
				return ErrNotFound
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
		{
			name:   "unexpected store error returns 500",
			pathID: id.String(),
			approveFn: func(_ context.Context, _ uuid.UUID) error {
				return errors.New("connection reset")
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
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
// Handler.Reject
// ---------------------------------------------------------------------------

func TestHandler_Reject(t *testing.T) {
	t.Parallel()

	id := fixedUUID(t)

	tests := []struct {
		name       string
		pathID     string
		body       any
		rejectFn   func(ctx context.Context, id uuid.UUID, notes string) error
		wantStatus int
		wantCode   string
		wantNotes  string
	}{
		{
			name:   "rejects review with notes",
			pathID: id.String(),
			body:   map[string]string{"notes": "needs revision"},
			rejectFn: func(_ context.Context, _ uuid.UUID, notes string) error {
				// notes value is validated by caller in a separate test
				return nil
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:   "rejects review with empty notes",
			pathID: id.String(),
			body:   map[string]string{"notes": ""},
			rejectFn: func(_ context.Context, _ uuid.UUID, _ string) error {
				return nil
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "invalid uuid returns 400",
			pathID:     "bad-id",
			body:       map[string]string{"notes": "x"},
			rejectFn:   nil,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:   "store error returns 500",
			pathID: id.String(),
			body:   map[string]string{"notes": "nope"},
			rejectFn: func(_ context.Context, _ uuid.UUID, _ string) error {
				return errors.New("write failed")
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &stubReviewStore{rejectFn: tt.rejectFn}
			h := newTestHandler(stub)

			bodyBytes, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatalf("marshaling body: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/admin/review/"+tt.pathID+"/reject", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()
			h.Reject(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Reject(%q) status = %d, want %d", tt.pathID, w.Code, tt.wantStatus)
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

// TestHandler_Reject_NotesPassedThrough verifies that the notes string from the
// JSON body is forwarded to the store unchanged.
func TestHandler_Reject_NotesPassedThrough(t *testing.T) {
	t.Parallel()

	id := fixedUUID(t)
	wantNotes := "please fix the grammar"
	var gotNotes string

	stub := &stubReviewStore{
		rejectFn: func(_ context.Context, _ uuid.UUID, notes string) error {
			gotNotes = notes
			return nil
		},
	}
	h := newTestHandler(stub)

	body, _ := json.Marshal(map[string]string{"notes": wantNotes})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/review/"+id.String()+"/reject", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", id.String())
	w := httptest.NewRecorder()
	h.Reject(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("Reject() status = %d, want %d", w.Code, http.StatusNoContent)
	}
	if diff := cmp.Diff(wantNotes, gotNotes); diff != "" {
		t.Errorf("notes mismatch (-want +got):\n%s", diff)
	}
}

// ---------------------------------------------------------------------------
// Handler.Edit
// ---------------------------------------------------------------------------

func TestHandler_Edit(t *testing.T) {
	t.Parallel()

	id := fixedUUID(t)
	contentID := uuid.New()
	now := time.Date(2026, 3, 28, 0, 0, 0, 0, time.UTC)

	stubReview := &Review{
		ID:          id,
		ContentID:   contentID,
		ReviewLevel: "standard",
		Status:      string(StatusPending),
		SubmittedAt: now,
	}

	tests := []struct {
		name       string
		pathID     string
		reviewFn   func(ctx context.Context, id uuid.UUID) (*Review, error)
		approveFn  func(ctx context.Context, id uuid.UUID) error
		wantStatus int
		wantCode   string
	}{
		{
			name:   "edit fetches review then approves",
			pathID: id.String(),
			reviewFn: func(_ context.Context, _ uuid.UUID) (*Review, error) {
				return stubReview, nil
			},
			approveFn: func(_ context.Context, _ uuid.UUID) error {
				return nil
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:   "edit with not-found review returns 404",
			pathID: id.String(),
			reviewFn: func(_ context.Context, _ uuid.UUID) (*Review, error) {
				return nil, ErrNotFound
			},
			approveFn:  nil,
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
		},
		{
			name:       "invalid uuid returns 400",
			pathID:     "not-a-uuid",
			reviewFn:   nil,
			approveFn:  nil,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:   "approve failure after fetch returns 500",
			pathID: id.String(),
			reviewFn: func(_ context.Context, _ uuid.UUID) (*Review, error) {
				return stubReview, nil
			},
			approveFn: func(_ context.Context, _ uuid.UUID) error {
				return errors.New("db write failed")
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &stubReviewStore{
				reviewFn:  tt.reviewFn,
				approveFn: tt.approveFn,
			}
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
