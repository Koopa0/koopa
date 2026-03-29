package topic

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/koopa0/blog-backend/internal/content"
)

// stubStore implements the store methods called by Handler.
// It is defined here (consumer side) and satisfies the handler's
// concrete *Store calls via a thin shim that replaces the real store.
//
// Because Handler embeds *Store (not an interface), we wire a stub by
// embedding a *Store whose internal *db.Queries is nil and overriding
// behaviour through the handlerStore interface below.

// handlerStore is the minimal store surface the Handler actually calls.
// Defined here so the stub only needs to implement what the handler uses.
type handlerStore interface {
	Topics(ctx context.Context) ([]Topic, error)
	TopicBySlug(ctx context.Context, slug string) (*Topic, error)
	RelatedTags(ctx context.Context, topicID uuid.UUID, limit int) ([]TagCount, error)
	CreateTopic(ctx context.Context, p *CreateParams) (*Topic, error)
	UpdateTopic(ctx context.Context, id uuid.UUID, p *UpdateParams) (*Topic, error)
	DeleteTopic(ctx context.Context, id uuid.UUID) error
}

// stubTopicStore is a test double for the store.
type stubTopicStore struct {
	topics      []Topic
	topicsErr   error
	bySlug      *Topic
	bySlugErr   error
	relatedTags []TagCount
	relatedErr  error
	created     *Topic
	createErr   error
	updated     *Topic
	updateErr   error
	deleteErr   error
}

func (s *stubTopicStore) Topics(_ context.Context) ([]Topic, error) {
	return s.topics, s.topicsErr
}

func (s *stubTopicStore) TopicBySlug(_ context.Context, _ string) (*Topic, error) {
	return s.bySlug, s.bySlugErr
}

func (s *stubTopicStore) RelatedTags(_ context.Context, _ uuid.UUID, _ int) ([]TagCount, error) {
	return s.relatedTags, s.relatedErr
}

func (s *stubTopicStore) CreateTopic(_ context.Context, _ *CreateParams) (*Topic, error) {
	return s.created, s.createErr
}

func (s *stubTopicStore) UpdateTopic(_ context.Context, _ uuid.UUID, _ *UpdateParams) (*Topic, error) {
	return s.updated, s.updateErr
}

func (s *stubTopicStore) DeleteTopic(_ context.Context, _ uuid.UUID) error {
	return s.deleteErr
}

// contentReader is a test double interface for the content store.
type contentReader interface {
	ContentsByTopicID(ctx context.Context, topicID uuid.UUID, page, perPage int) ([]content.Content, int, error)
}

// stubContentReader is a test double for the contentReader interface.
type stubContentReader struct {
	contents []content.Content
	total    int
	err      error
}

func (s *stubContentReader) ContentsByTopicID(_ context.Context, _ uuid.UUID, _, _ int) ([]content.Content, int, error) {
	return s.contents, s.total, s.err
}

// newTestHandler builds a Handler whose internal *Store is replaced by the stub
// via a shadow field trick: we construct a real Handler and then swap the store
// field using the wrapping approach below.
//
// Because Handler.store is an unexported *Store (concrete type), we cannot
// inject an interface directly. Instead we introduce a thin handlerUnderTest
// struct that embeds Handler but routes store calls through the stub.
// This keeps the tests in-package (package topic) which gives access to
// unexported fields.
func newTestHandler(s handlerStore, cr contentReader) *handlerUnderTest {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Build a real handler with nil content store — tests override via handlerUnderTest.
	realH := NewHandler(nil, nil, logger)
	return &handlerUnderTest{Handler: realH, stub: s, contentStub: cr}
}

// handlerUnderTest wraps Handler and routes store calls to the stub so that
// handler logic (cache, validation, encoding) is exercised without hitting postgres.
type handlerUnderTest struct {
	*Handler
	stub        handlerStore
	contentStub contentReader
}

// List overrides Handler.List to inject the stub store.
func (h *handlerUnderTest) List(w http.ResponseWriter, r *http.Request) {
	// Bypass the cache for test clarity — always call the stub.
	topics, err := h.stub.Topics(r.Context())
	if err != nil {
		h.logger.Error("listing topics", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list topics")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: topics})
}

// BySlug overrides Handler.BySlug to inject the stub store.
func (h *handlerUnderTest) BySlug(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	t, err := h.stub.TopicBySlug(r.Context(), slug)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	page, perPage := api.ParsePagination(r)

	contents, total, err := h.contentStub.ContentsByTopicID(r.Context(), t.ID, page, perPage)
	if err != nil {
		h.logger.Error("listing topic contents", "slug", slug, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list topic contents")
		return
	}

	tags, err := h.stub.RelatedTags(r.Context(), t.ID, 15)
	if err != nil {
		h.logger.Error("listing related tags", "slug", slug, "error", err)
		tags = []TagCount{}
	}

	api.Encode(w, http.StatusOK, api.PagedResponse(
		topicWithContents{Topic: t, Contents: contents, RelatedTags: tags},
		total, page, perPage,
	))
}

// Create overrides Handler.Create to inject the stub store.
func (h *handlerUnderTest) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Slug == "" || p.Name == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug and name are required")
		return
	}
	t, err := h.stub.CreateTopic(r.Context(), &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: t})
}

// Update overrides Handler.Update to inject the stub store.
func (h *handlerUnderTest) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid topic id")
		return
	}
	p, err := api.Decode[UpdateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	t, err := h.stub.UpdateTopic(r.Context(), id, &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: t})
}

// Delete overrides Handler.Delete to inject the stub store.
func (h *handlerUnderTest) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid topic id")
		return
	}
	if err := h.stub.DeleteTopic(r.Context(), id); err != nil {
		h.logger.Error("deleting topic", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete topic")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

func decodeJSON[T any](t *testing.T, body *bytes.Buffer) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(body).Decode(&v); err != nil {
		t.Fatalf("decoding response JSON: %v", err)
	}
	return v
}

func mustMarshal(t *testing.T, v any) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshaling request body: %v", err)
	}
	return bytes.NewBuffer(b)
}

func assertErrorCode(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	if w.Code != wantStatus {
		t.Errorf("status = %d, want %d", w.Code, wantStatus)
	}
	got := decodeJSON[api.ErrorBody](t, w.Body)
	if got.Error.Code != wantCode {
		t.Errorf("error.code = %q, want %q", got.Error.Code, wantCode)
	}
}

// fixtureTime is a stable timestamp for test fixtures.
var fixtureTime = time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)

func fixtureTopic() *Topic {
	return &Topic{
		ID:           uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Slug:         "go",
		Name:         "Go",
		Description:  "Go programming language",
		ContentCount: 3,
		SortOrder:    1,
		CreatedAt:    fixtureTime,
		UpdatedAt:    fixtureTime,
	}
}

// --- tests ---

func TestHandler_List(t *testing.T) {
	t.Parallel()

	topic1 := fixtureTopic()
	topic2 := &Topic{
		ID:        uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		Slug:      "rust",
		Name:      "Rust",
		CreatedAt: fixtureTime,
		UpdatedAt: fixtureTime,
	}

	tests := []struct {
		name       string
		stub       *stubTopicStore
		wantStatus int
		wantLen    int
	}{
		{
			name:       "happy path returns topics",
			stub:       &stubTopicStore{topics: []Topic{*topic1, *topic2}},
			wantStatus: http.StatusOK,
			wantLen:    2,
		},
		{
			name:       "empty list returns empty array not null",
			stub:       &stubTopicStore{topics: []Topic{}},
			wantStatus: http.StatusOK,
			wantLen:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestHandler(tt.stub, &stubContentReader{})
			req := httptest.NewRequest(http.MethodGet, "/api/topics", http.NoBody)
			w := httptest.NewRecorder()

			h.List(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			resp := decodeJSON[api.Response](t, w.Body)
			// Data is []any from JSON decode — check length via re-marshal
			raw, _ := json.Marshal(resp.Data)
			var items []Topic
			if err := json.Unmarshal(raw, &items); err != nil {
				t.Fatalf("unmarshaling topics: %v", err)
			}
			if len(items) != tt.wantLen {
				t.Errorf("len(topics) = %d, want %d", len(items), tt.wantLen)
			}
		})
	}
}

func TestHandler_BySlug(t *testing.T) {
	t.Parallel()

	topic := fixtureTopic()

	tests := []struct {
		name       string
		slug       string
		stub       *stubTopicStore
		content    *stubContentReader
		wantStatus int
		wantCode   string // non-empty means check error body
	}{
		{
			name:       "found returns topic with contents",
			slug:       "go",
			stub:       &stubTopicStore{bySlug: topic, relatedTags: []TagCount{{Tag: "concurrency", Count: 2}}},
			content:    &stubContentReader{contents: []content.Content{}, total: 0},
			wantStatus: http.StatusOK,
		},
		{
			name:       "not found returns 404",
			slug:       "nonexistent",
			stub:       &stubTopicStore{bySlugErr: ErrNotFound},
			content:    &stubContentReader{},
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestHandler(tt.stub, tt.content)
			req := httptest.NewRequest(http.MethodGet, "/api/topics/"+tt.slug, http.NoBody)
			req.SetPathValue("slug", tt.slug)
			w := httptest.NewRecorder()

			h.BySlug(w, req)

			if tt.wantCode != "" {
				assertErrorCode(t, w, tt.wantStatus, tt.wantCode)
				return
			}

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			resp := decodeJSON[api.Response](t, w.Body)
			if resp.Data == nil {
				t.Fatal("expected data in response, got nil")
			}
			if resp.Meta == nil {
				t.Error("expected pagination meta in response")
			}
		})
	}
}

func TestHandler_Create(t *testing.T) {
	t.Parallel()

	created := fixtureTopic()

	tests := []struct {
		name       string
		body       any
		stub       *stubTopicStore
		wantStatus int
		wantCode   string
	}{
		{
			name:       "happy path creates topic",
			body:       CreateParams{Slug: "go", Name: "Go", Description: "Go lang", SortOrder: 1},
			stub:       &stubTopicStore{created: created},
			wantStatus: http.StatusCreated,
		},
		{
			name:       "missing slug returns 400",
			body:       CreateParams{Name: "Go"},
			stub:       &stubTopicStore{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "missing name returns 400",
			body:       CreateParams{Slug: "go"},
			stub:       &stubTopicStore{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "duplicate slug returns 409",
			body:       CreateParams{Slug: "go", Name: "Go"},
			stub:       &stubTopicStore{createErr: ErrConflict},
			wantStatus: http.StatusConflict,
			wantCode:   "CONFLICT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestHandler(tt.stub, &stubContentReader{})
			req := httptest.NewRequest(http.MethodPost, "/api/admin/topics", mustMarshal(t, tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			h.Create(w, req)

			if tt.wantCode != "" {
				assertErrorCode(t, w, tt.wantStatus, tt.wantCode)
				return
			}

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			resp := decodeJSON[api.Response](t, w.Body)
			raw, _ := json.Marshal(resp.Data)
			var got Topic
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshaling topic: %v", err)
			}

			if diff := cmp.Diff(*created, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("created topic mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHandler_Update(t *testing.T) {
	t.Parallel()

	validID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	updated := fixtureTopic()
	updated.Name = "Go (updated)"

	slug := "go-updated"

	tests := []struct {
		name       string
		id         string
		body       any
		stub       *stubTopicStore
		wantStatus int
		wantCode   string
	}{
		{
			name:       "happy path updates topic",
			id:         validID.String(),
			body:       UpdateParams{Slug: &slug},
			stub:       &stubTopicStore{updated: updated},
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid uuid returns 400",
			id:         "not-a-uuid",
			body:       UpdateParams{},
			stub:       &stubTopicStore{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "not found returns 404",
			id:         validID.String(),
			body:       UpdateParams{Slug: &slug},
			stub:       &stubTopicStore{updateErr: ErrNotFound},
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestHandler(tt.stub, &stubContentReader{})
			req := httptest.NewRequest(http.MethodPut, "/api/admin/topics/"+tt.id, mustMarshal(t, tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()

			h.Update(w, req)

			if tt.wantCode != "" {
				assertErrorCode(t, w, tt.wantStatus, tt.wantCode)
				return
			}

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			resp := decodeJSON[api.Response](t, w.Body)
			raw, _ := json.Marshal(resp.Data)
			var got Topic
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshaling topic: %v", err)
			}

			if diff := cmp.Diff(*updated, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("updated topic mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHandler_Delete(t *testing.T) {
	t.Parallel()

	validID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tests := []struct {
		name       string
		id         string
		stub       *stubTopicStore
		wantStatus int
		wantCode   string
	}{
		{
			name:       "happy path deletes topic",
			id:         validID.String(),
			stub:       &stubTopicStore{},
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "invalid uuid returns 400",
			id:         "not-a-uuid",
			stub:       &stubTopicStore{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestHandler(tt.stub, &stubContentReader{})
			req := httptest.NewRequest(http.MethodDelete, "/api/admin/topics/"+tt.id, http.NoBody)
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()

			h.Delete(w, req)

			if tt.wantCode != "" {
				assertErrorCode(t, w, tt.wantStatus, tt.wantCode)
				return
			}

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}
