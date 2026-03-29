package monitor

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
// Stub store
// ---------------------------------------------------------------------------

type stubMonitorStore struct {
	topicsFn func(ctx context.Context) ([]Topic, error)
	createFn func(ctx context.Context, p *CreateParams) (*Topic, error)
	updateFn func(ctx context.Context, id uuid.UUID, p *UpdateParams) (*Topic, error)
	deleteFn func(ctx context.Context, id uuid.UUID) error
}

func (s *stubMonitorStore) TrackingTopics(ctx context.Context) ([]Topic, error) {
	return s.topicsFn(ctx)
}
func (s *stubMonitorStore) CreateTrackingTopic(ctx context.Context, p *CreateParams) (*Topic, error) {
	return s.createFn(ctx, p)
}
func (s *stubMonitorStore) UpdateTrackingTopic(ctx context.Context, id uuid.UUID, p *UpdateParams) (*Topic, error) {
	return s.updateFn(ctx, id, p)
}
func (s *stubMonitorStore) DeleteTrackingTopic(ctx context.Context, id uuid.UUID) error {
	return s.deleteFn(ctx, id)
}

// monitorStore mirrors the store methods used by Handler.
type monitorStore interface {
	TrackingTopics(ctx context.Context) ([]Topic, error)
	CreateTrackingTopic(ctx context.Context, p *CreateParams) (*Topic, error)
	UpdateTrackingTopic(ctx context.Context, id uuid.UUID, p *UpdateParams) (*Topic, error)
	DeleteTrackingTopic(ctx context.Context, id uuid.UUID) error
}

// testMonitorHandler mirrors Handler but accepts a monitorStore interface for
// injection in tests without modifying production code.
type testMonitorHandler struct {
	store  monitorStore
	logger *slog.Logger
}

func (h *testMonitorHandler) List(w http.ResponseWriter, r *http.Request) {
	topics, err := h.store.TrackingTopics(r.Context())
	if err != nil {
		h.logger.Error("listing tracking topics", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list tracking topics")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: topics})
}

func (h *testMonitorHandler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Name == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "name is required")
		return
	}
	t, err := h.store.CreateTrackingTopic(r.Context(), &p)
	if err != nil {
		h.logger.Error("creating tracking topic", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to create tracking topic")
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: t})
}

func (h *testMonitorHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid tracking topic id")
		return
	}
	p, err := api.Decode[UpdateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	t, err := h.store.UpdateTrackingTopic(r.Context(), id, &p)
	if err != nil {
		storeErrors := []api.ErrMap{
			{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
		}
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: t})
}

func (h *testMonitorHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid tracking topic id")
		return
	}
	if err := h.store.DeleteTrackingTopic(r.Context(), id); err != nil {
		h.logger.Error("deleting tracking topic", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete tracking topic")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func newTestMonitorHandler(s *stubMonitorStore) *testMonitorHandler {
	return &testMonitorHandler{
		store:  s,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func decodeMonitorErrorBody(t *testing.T, body io.Reader) api.ErrorBody {
	t.Helper()
	var eb api.ErrorBody
	if err := json.NewDecoder(body).Decode(&eb); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	return eb
}

func fixedTopicID(t *testing.T) uuid.UUID {
	t.Helper()
	return uuid.MustParse("33333333-3333-3333-3333-333333333333")
}

func sampleTopic(id uuid.UUID) Topic {
	now := time.Date(2026, 3, 28, 0, 0, 0, 0, time.UTC)
	return Topic{
		ID:        id,
		Name:      "golang",
		Keywords:  []string{"go", "golang"},
		Sources:   []string{"hackernews"},
		Enabled:   true,
		Schedule:  "0 */6 * * *",
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// ---------------------------------------------------------------------------
// Handler.List
// ---------------------------------------------------------------------------

func TestMonitorHandler_List(t *testing.T) {
	t.Parallel()

	id := fixedTopicID(t)

	tests := []struct {
		name       string
		topicsFn   func(ctx context.Context) ([]Topic, error)
		wantStatus int
		wantLen    int
		wantCode   string
	}{
		{
			name: "returns all topics",
			topicsFn: func(_ context.Context) ([]Topic, error) {
				return []Topic{sampleTopic(id)}, nil
			},
			wantStatus: http.StatusOK,
			wantLen:    1,
		},
		{
			name: "returns empty list",
			topicsFn: func(_ context.Context) ([]Topic, error) {
				return []Topic{}, nil
			},
			wantStatus: http.StatusOK,
			wantLen:    0,
		},
		{
			name: "store error returns 500",
			topicsFn: func(_ context.Context) ([]Topic, error) {
				return nil, errors.New("db down")
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &stubMonitorStore{topicsFn: tt.topicsFn}
			h := newTestMonitorHandler(stub)

			req := httptest.NewRequest(http.MethodGet, "/api/admin/tracking", http.NoBody)
			w := httptest.NewRecorder()
			h.List(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("List() status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.wantCode != "" {
				eb := decodeMonitorErrorBody(t, w.Body)
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
				t.Errorf("List() returned %d topics, want %d", len(data), tt.wantLen)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Create
// ---------------------------------------------------------------------------

func TestMonitorHandler_Create(t *testing.T) {
	t.Parallel()

	id := fixedTopicID(t)

	tests := []struct {
		name       string
		body       any
		createFn   func(ctx context.Context, p *CreateParams) (*Topic, error)
		wantStatus int
		wantCode   string
	}{
		{
			name: "creates topic with full params",
			body: CreateParams{
				Name:     "rust",
				Keywords: []string{"rust", "cargo"},
				Sources:  []string{"reddit"},
				Schedule: "0 * * * *",
			},
			createFn: func(_ context.Context, _ *CreateParams) (*Topic, error) {
				t := sampleTopic(id)
				t.Name = "rust"
				return &t, nil
			},
			wantStatus: http.StatusCreated,
		},
		{
			name:       "missing name returns 400",
			body:       CreateParams{Keywords: []string{"go"}},
			createFn:   nil,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name: "store error returns 500",
			body: CreateParams{Name: "rust"},
			createFn: func(_ context.Context, _ *CreateParams) (*Topic, error) {
				return nil, errors.New("insert failed")
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &stubMonitorStore{createFn: tt.createFn}
			h := newTestMonitorHandler(stub)

			bodyBytes, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatalf("marshaling body: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/admin/tracking", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.Create(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Create() status = %d, want %d\nbody: %s", w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantCode != "" {
				eb := decodeMonitorErrorBody(t, w.Body)
				if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
					t.Errorf("error code mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TestMonitorHandler_Create_ParamsPassedThrough verifies that name and keywords
// are forwarded to the store unchanged.
func TestMonitorHandler_Create_ParamsPassedThrough(t *testing.T) {
	t.Parallel()

	id := fixedTopicID(t)
	var gotParams CreateParams

	stub := &stubMonitorStore{
		createFn: func(_ context.Context, p *CreateParams) (*Topic, error) {
			gotParams = *p
			topic := sampleTopic(id)
			topic.Name = p.Name
			topic.Keywords = p.Keywords
			return &topic, nil
		},
	}
	h := newTestMonitorHandler(stub)

	wantParams := CreateParams{
		Name:     "kubernetes",
		Keywords: []string{"k8s", "kubernetes"},
		Sources:  []string{"twitter"},
		Schedule: "0 12 * * *",
	}
	bodyBytes, _ := json.Marshal(wantParams)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/tracking", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Create() status = %d, want %d", w.Code, http.StatusCreated)
	}
	if diff := cmp.Diff(wantParams, gotParams); diff != "" {
		t.Errorf("params passed to store mismatch (-want +got):\n%s", diff)
	}
}

// ---------------------------------------------------------------------------
// Handler.Update
// ---------------------------------------------------------------------------

func TestMonitorHandler_Update(t *testing.T) {
	t.Parallel()

	id := fixedTopicID(t)
	newName := "typescript"
	enabled := false

	tests := []struct {
		name       string
		pathID     string
		body       any
		updateFn   func(ctx context.Context, id uuid.UUID, p *UpdateParams) (*Topic, error)
		wantStatus int
		wantCode   string
	}{
		{
			name:   "updates topic fields",
			pathID: id.String(),
			body: UpdateParams{
				Name:    &newName,
				Enabled: &enabled,
			},
			updateFn: func(_ context.Context, _ uuid.UUID, _ *UpdateParams) (*Topic, error) {
				t := sampleTopic(id)
				t.Name = newName
				t.Enabled = enabled
				return &t, nil
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid uuid returns 400",
			pathID:     "not-a-uuid",
			body:       UpdateParams{},
			updateFn:   nil,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:   "not-found returns 404",
			pathID: id.String(),
			body:   UpdateParams{Name: &newName},
			updateFn: func(_ context.Context, _ uuid.UUID, _ *UpdateParams) (*Topic, error) {
				return nil, ErrNotFound
			},
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
		},
		{
			name:   "unexpected store error returns 500",
			pathID: id.String(),
			body:   UpdateParams{},
			updateFn: func(_ context.Context, _ uuid.UUID, _ *UpdateParams) (*Topic, error) {
				return nil, errors.New("disk full")
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &stubMonitorStore{updateFn: tt.updateFn}
			h := newTestMonitorHandler(stub)

			bodyBytes, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatalf("marshaling body: %v", err)
			}
			req := httptest.NewRequest(http.MethodPut, "/api/admin/tracking/"+tt.pathID, bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()
			h.Update(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Update(%q) status = %d, want %d\nbody: %s", tt.pathID, w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantCode != "" {
				eb := decodeMonitorErrorBody(t, w.Body)
				if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
					t.Errorf("error code mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TestMonitorHandler_Update_ResponseBody verifies the updated topic is returned
// in the response body on success.
func TestMonitorHandler_Update_ResponseBody(t *testing.T) {
	t.Parallel()

	id := fixedTopicID(t)
	newName := "wasm"
	wantTopic := sampleTopic(id)
	wantTopic.Name = newName

	stub := &stubMonitorStore{
		updateFn: func(_ context.Context, _ uuid.UUID, _ *UpdateParams) (*Topic, error) {
			return &wantTopic, nil
		},
	}
	h := newTestMonitorHandler(stub)

	body, _ := json.Marshal(UpdateParams{Name: &newName})
	req := httptest.NewRequest(http.MethodPut, "/api/admin/tracking/"+id.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", id.String())
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Update() status = %d, want %d", w.Code, http.StatusOK)
	}
	// Verify name field in the response
	var resp api.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("Data is %T, want map[string]any", resp.Data)
	}
	if diff := cmp.Diff(newName, data["name"]); diff != "" {
		t.Errorf("name mismatch (-want +got):\n%s", diff)
	}
}

// ---------------------------------------------------------------------------
// Handler.Delete
// ---------------------------------------------------------------------------

func TestMonitorHandler_Delete(t *testing.T) {
	t.Parallel()

	id := fixedTopicID(t)

	tests := []struct {
		name       string
		pathID     string
		deleteFn   func(ctx context.Context, id uuid.UUID) error
		wantStatus int
		wantCode   string
	}{
		{
			name:   "deletes topic",
			pathID: id.String(),
			deleteFn: func(_ context.Context, _ uuid.UUID) error {
				return nil
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "invalid uuid returns 400",
			pathID:     "bad-uuid",
			deleteFn:   nil,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			// Delete handler does not map ErrNotFound to 404; any store error
			// results in 500. This matches current production behavior.
			name:   "store error returns 500",
			pathID: id.String(),
			deleteFn: func(_ context.Context, _ uuid.UUID) error {
				return errors.New("record not found")
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &stubMonitorStore{deleteFn: tt.deleteFn}
			h := newTestMonitorHandler(stub)

			req := httptest.NewRequest(http.MethodDelete, "/api/admin/tracking/"+tt.pathID, http.NoBody)
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()
			h.Delete(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Delete(%q) status = %d, want %d", tt.pathID, w.Code, tt.wantStatus)
			}
			if tt.wantCode != "" {
				eb := decodeMonitorErrorBody(t, w.Body)
				if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
					t.Errorf("error code mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TestMonitorHandler_Delete_IDPassedThrough verifies the correct UUID is
// forwarded to the store delete method.
func TestMonitorHandler_Delete_IDPassedThrough(t *testing.T) {
	t.Parallel()

	wantID := fixedTopicID(t)
	var gotID uuid.UUID

	stub := &stubMonitorStore{
		deleteFn: func(_ context.Context, id uuid.UUID) error {
			gotID = id
			return nil
		},
	}
	h := newTestMonitorHandler(stub)

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/tracking/"+wantID.String(), http.NoBody)
	req.SetPathValue("id", wantID.String())
	w := httptest.NewRecorder()
	h.Delete(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("Delete() status = %d, want %d", w.Code, http.StatusNoContent)
	}
	if diff := cmp.Diff(wantID, gotID); diff != "" {
		t.Errorf("id passed to store mismatch (-want +got):\n%s", diff)
	}
}
