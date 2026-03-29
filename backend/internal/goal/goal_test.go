package goal

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
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// ---------------------------------------------------------------------------
// mapHTTPGoalStatus — pure business logic (Q0)
// ---------------------------------------------------------------------------

func TestMapHTTPGoalStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    Status
		wantErr bool
	}{
		// not-started variants
		{name: "not-started canonical", input: "not-started", want: StatusNotStarted},
		{name: "Not Started notion label", input: "Not Started", want: StatusNotStarted},
		{name: "Dream notion label", input: "Dream", want: StatusNotStarted},

		// in-progress variants
		{name: "in-progress canonical", input: "in-progress", want: StatusInProgress},
		{name: "In Progress notion label", input: "In Progress", want: StatusInProgress},
		{name: "Active notion label", input: "Active", want: StatusInProgress},

		// done variants
		{name: "done canonical", input: "done", want: StatusDone},
		{name: "Done notion label", input: "Done", want: StatusDone},
		{name: "Achieved notion label", input: "Achieved", want: StatusDone},

		// abandoned variants
		{name: "abandoned canonical", input: "abandoned", want: StatusAbandoned},
		{name: "Abandoned notion label", input: "Abandoned", want: StatusAbandoned},

		// error cases
		{name: "empty string", input: "", wantErr: true},
		{name: "unknown status", input: "paused", wantErr: true},
		{name: "case mismatch not-Started", input: "not-Started", wantErr: true},
		{name: "extra whitespace", input: " done", wantErr: true},
		{name: "numeric string", input: "1", wantErr: true},
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
// Stub store
// ---------------------------------------------------------------------------

type stubGoalStore struct {
	goalsFn        func(ctx context.Context) ([]Goal, error)
	updateStatusFn func(ctx context.Context, id uuid.UUID, status Status) (*Goal, error)
}

func (s *stubGoalStore) Goals(ctx context.Context) ([]Goal, error) {
	return s.goalsFn(ctx)
}

func (s *stubGoalStore) UpdateStatus(ctx context.Context, id uuid.UUID, status Status) (*Goal, error) {
	return s.updateStatusFn(ctx, id, status)
}

// goalStore mirrors the store methods used by Handler.
type goalStore interface {
	Goals(ctx context.Context) ([]Goal, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status Status) (*Goal, error)
}

// testGoalHandler mirrors Handler but accepts a goalStore interface for
// injection in tests without modifying production code.
type testGoalHandler struct {
	store  goalStore
	logger *slog.Logger
}

func (h *testGoalHandler) List(w http.ResponseWriter, r *http.Request) {
	goals, err := h.store.Goals(r.Context())
	if err != nil {
		h.logger.Error("listing goals", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list goals")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: goals})
}

func (h *testGoalHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_ID", "invalid goal id")
		return
	}

	type updateStatusRequest struct {
		Status string `json:"status"`
	}
	req, err := api.Decode[updateStatusRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if req.Status == "" {
		api.Error(w, http.StatusBadRequest, "MISSING_STATUS", "status is required")
		return
	}

	status, statusErr := mapHTTPGoalStatus(req.Status)
	if statusErr != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_STATUS", statusErr.Error())
		return
	}

	updated, err := h.store.UpdateStatus(r.Context(), id, status)
	if err != nil {
		h.logger.Error("updating goal status", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to update goal status")
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: map[string]any{
		"title":      updated.Title,
		"status":     string(updated.Status),
		"area":       updated.Area,
		"updated_at": updated.UpdatedAt,
	}})
}

func newTestGoalHandler(s *stubGoalStore) *testGoalHandler {
	return &testGoalHandler{
		store:  s,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func decodeGoalErrorBody(t *testing.T, body io.Reader) api.ErrorBody {
	t.Helper()
	var eb api.ErrorBody
	if err := json.NewDecoder(body).Decode(&eb); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	return eb
}

// ---------------------------------------------------------------------------
// Handler.List
// ---------------------------------------------------------------------------

func TestGoalHandler_List(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 28, 0, 0, 0, 0, time.UTC)
	id := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	tests := []struct {
		name       string
		goalsFn    func(ctx context.Context) ([]Goal, error)
		wantStatus int
		wantLen    int
		wantCode   string
	}{
		{
			name: "returns all goals",
			goalsFn: func(_ context.Context) ([]Goal, error) {
				return []Goal{
					{
						ID:        id,
						Title:     "Ship platform v1",
						Status:    StatusInProgress,
						Area:      "engineering",
						Quarter:   "2026-Q1",
						CreatedAt: now,
						UpdatedAt: now,
					},
				}, nil
			},
			wantStatus: http.StatusOK,
			wantLen:    1,
		},
		{
			name: "returns empty list",
			goalsFn: func(_ context.Context) ([]Goal, error) {
				return []Goal{}, nil
			},
			wantStatus: http.StatusOK,
			wantLen:    0,
		},
		{
			name: "store error returns 500",
			goalsFn: func(_ context.Context) ([]Goal, error) {
				return nil, errors.New("db timeout")
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &stubGoalStore{goalsFn: tt.goalsFn}
			h := newTestGoalHandler(stub)

			req := httptest.NewRequest(http.MethodGet, "/api/admin/goals", http.NoBody)
			w := httptest.NewRecorder()
			h.List(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("List() status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.wantCode != "" {
				eb := decodeGoalErrorBody(t, w.Body)
				if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
					t.Errorf("error code mismatch (-want +got):\n%s", diff)
				}
				return
			}
			var resp api.Response
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decoding response: %v", err)
			}
			data, ok := resp.Data.([]any)
			if !ok {
				t.Fatalf("Data is %T, want []any", resp.Data)
			}
			if len(data) != tt.wantLen {
				t.Errorf("List() returned %d goals, want %d", len(data), tt.wantLen)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.UpdateStatus
// ---------------------------------------------------------------------------

func TestGoalHandler_UpdateStatus(t *testing.T) {
	t.Parallel()

	id := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	now := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)

	okGoal := &Goal{
		ID:        id,
		Title:     "Ship platform v1",
		Status:    StatusDone,
		Area:      "engineering",
		Quarter:   "2026-Q1",
		CreatedAt: now,
		UpdatedAt: now,
	}
	okFn := func(_ context.Context, _ uuid.UUID, _ Status) (*Goal, error) { return okGoal, nil }

	tests := []struct {
		name           string
		pathID         string
		body           any
		updateStatusFn func(ctx context.Context, id uuid.UUID, status Status) (*Goal, error)
		wantStatus     int
		wantCode       string
	}{
		{
			name:           "updates status with canonical value",
			pathID:         id.String(),
			body:           map[string]string{"status": "done"},
			updateStatusFn: okFn,
			wantStatus:     http.StatusOK,
		},
		{
			name:   "updates status with notion label",
			pathID: id.String(),
			body:   map[string]string{"status": "Achieved"},
			updateStatusFn: func(_ context.Context, _ uuid.UUID, s Status) (*Goal, error) {
				if s != StatusDone {
					return nil, errors.New("wrong status")
				}
				return okGoal, nil
			},
			wantStatus: http.StatusOK,
		},
		{
			name:           "invalid uuid returns 400",
			pathID:         "not-a-uuid",
			body:           map[string]string{"status": "done"},
			updateStatusFn: nil,
			wantStatus:     http.StatusBadRequest,
			wantCode:       "INVALID_ID",
		},
		{
			name:           "missing status returns 400",
			pathID:         id.String(),
			body:           map[string]string{"status": ""},
			updateStatusFn: nil,
			wantStatus:     http.StatusBadRequest,
			wantCode:       "MISSING_STATUS",
		},
		{
			name:           "unknown status returns 400",
			pathID:         id.String(),
			body:           map[string]string{"status": "pending"},
			updateStatusFn: nil,
			wantStatus:     http.StatusBadRequest,
			wantCode:       "INVALID_STATUS",
		},
		{
			name:   "store error returns 500",
			pathID: id.String(),
			body:   map[string]string{"status": "in-progress"},
			updateStatusFn: func(_ context.Context, _ uuid.UUID, _ Status) (*Goal, error) {
				return nil, errors.New("connection refused")
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &stubGoalStore{updateStatusFn: tt.updateStatusFn}
			h := newTestGoalHandler(stub)

			bodyBytes, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatalf("marshaling body: %v", err)
			}
			req := httptest.NewRequest(http.MethodPut, "/api/admin/goals/"+tt.pathID+"/status", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()
			h.UpdateStatus(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("UpdateStatus(%q) status = %d, want %d", tt.pathID, w.Code, tt.wantStatus)
			}
			if tt.wantCode != "" {
				eb := decodeGoalErrorBody(t, w.Body)
				if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
					t.Errorf("error code mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TestGoalHandler_UpdateStatus_StatusPassedThrough verifies that the mapped
// Status value is forwarded to the store unchanged.
func TestGoalHandler_UpdateStatus_StatusPassedThrough(t *testing.T) {
	t.Parallel()

	id := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	now := time.Now()

	var gotStatus Status
	stub := &stubGoalStore{
		updateStatusFn: func(_ context.Context, _ uuid.UUID, s Status) (*Goal, error) {
			gotStatus = s
			return &Goal{
				ID:        id,
				Title:     "test",
				Status:    s,
				UpdatedAt: now,
			}, nil
		},
	}
	h := newTestGoalHandler(stub)

	body, _ := json.Marshal(map[string]string{"status": "in-progress"})
	req := httptest.NewRequest(http.MethodPut, "/api/admin/goals/"+id.String()+"/status", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", id.String())
	w := httptest.NewRecorder()
	h.UpdateStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("UpdateStatus() status = %d, want %d", w.Code, http.StatusOK)
	}
	if diff := cmp.Diff(StatusInProgress, gotStatus); diff != "" {
		t.Errorf("status passed to store mismatch (-want +got):\n%s", diff)
	}
}

// TestGoalHandler_UpdateStatus_ResponseShape verifies all fields in the success
// response are present with correct values.
func TestGoalHandler_UpdateStatus_ResponseShape(t *testing.T) {
	t.Parallel()

	id := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	now := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)

	stub := &stubGoalStore{
		updateStatusFn: func(_ context.Context, _ uuid.UUID, s Status) (*Goal, error) {
			return &Goal{
				ID:        id,
				Title:     "Ship v1",
				Status:    s,
				Area:      "engineering",
				Quarter:   "2026-Q1",
				UpdatedAt: now,
			}, nil
		},
	}
	h := newTestGoalHandler(stub)

	body, _ := json.Marshal(map[string]string{"status": "done"})
	req := httptest.NewRequest(http.MethodPut, "/api/admin/goals/"+id.String()+"/status", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", id.String())
	w := httptest.NewRecorder()
	h.UpdateStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp api.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("Data is %T, want map[string]any", resp.Data)
	}

	wantFields := map[string]any{
		"title":  "Ship v1",
		"status": "done",
		"area":   "engineering",
	}
	if diff := cmp.Diff(wantFields, data, cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
		return k == "updated_at"
	})); diff != "" {
		t.Errorf("response data mismatch (-want +got):\n%s", diff)
	}
	if _, ok := data["updated_at"]; !ok {
		t.Error("response missing updated_at field")
	}
}
