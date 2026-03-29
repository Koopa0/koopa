package topic

import (
	"bytes"
	"encoding/json"
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
// Helpers
// ---------------------------------------------------------------------------

func decodeErrorResponse(t *testing.T, w *httptest.ResponseRecorder) api.ErrorBody {
	t.Helper()
	var eb api.ErrorBody
	if err := json.NewDecoder(w.Body).Decode(&eb); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	return eb
}

func mustMarshal(t *testing.T, v any) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshaling request body: %v", err)
	}
	return bytes.NewBuffer(b)
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

// ---------------------------------------------------------------------------
// Handler.Create — validation (real Handler, nil store)
// Store interaction tested via integration tests.
// ---------------------------------------------------------------------------

func TestHandler_Create_Validation(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, nil, slog.New(slog.DiscardHandler))

	tests := []struct {
		name       string
		body       any
		wantStatus int
		wantCode   string
	}{
		{
			name:       "missing slug returns 400",
			body:       CreateParams{Name: "Go"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "missing name returns 400",
			body:       CreateParams{Slug: "go"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "empty body returns 400",
			body:       nil,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var bodyBuf *bytes.Buffer
			if tt.body == nil {
				bodyBuf = bytes.NewBuffer(nil)
			} else {
				bodyBuf = mustMarshal(t, tt.body)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/admin/topics", bodyBuf)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.Create(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Create() status = %d, want %d (body: %s)", w.Code, tt.wantStatus, w.Body.String())
			}
			eb := decodeErrorResponse(t, w)
			if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
				t.Errorf("error code mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Update — validation (real Handler, nil store)
// Store interaction tested via integration tests.
// ---------------------------------------------------------------------------

func TestHandler_Update_Validation(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, nil, slog.New(slog.DiscardHandler))

	slug := "go-updated"

	tests := []struct {
		name       string
		id         string
		body       any
		wantStatus int
		wantCode   string
	}{
		{
			name:       "invalid uuid returns 400",
			id:         "not-a-uuid",
			body:       UpdateParams{Slug: &slug},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "malformed JSON returns 400",
			id:         uuid.MustParse("11111111-1111-1111-1111-111111111111").String(),
			body:       nil, // will be sent as empty body
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var bodyBuf *bytes.Buffer
			if tt.body == nil {
				bodyBuf = bytes.NewBuffer(nil)
			} else {
				bodyBuf = mustMarshal(t, tt.body)
			}

			req := httptest.NewRequest(http.MethodPut, "/api/admin/topics/"+tt.id, bodyBuf)
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()
			h.Update(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Update(%q) status = %d, want %d (body: %s)", tt.id, w.Code, tt.wantStatus, w.Body.String())
			}
			eb := decodeErrorResponse(t, w)
			if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
				t.Errorf("error code mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Delete — validation (real Handler, nil store)
// Store interaction tested via integration tests.
// ---------------------------------------------------------------------------

func TestHandler_Delete_Validation(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, nil, slog.New(slog.DiscardHandler))

	tests := []struct {
		name       string
		id         string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "invalid uuid returns 400",
			id:         "not-a-uuid",
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodDelete, "/api/admin/topics/"+tt.id, http.NoBody)
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()
			h.Delete(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Delete(%q) status = %d, want %d", tt.id, w.Code, tt.wantStatus)
			}
			eb := decodeErrorResponse(t, w)
			if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
				t.Errorf("error code mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Handler.List, Handler.BySlug, and store-interaction paths for Create/Update/Delete
// are tested via integration tests (require a real database connection).
