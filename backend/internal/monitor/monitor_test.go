package monitor

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

func decodeMonitorErrorBody(t *testing.T, w *httptest.ResponseRecorder) api.ErrorBody {
	t.Helper()
	var eb api.ErrorBody
	if err := json.NewDecoder(w.Body).Decode(&eb); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	return eb
}

// ---------------------------------------------------------------------------
// Handler.Create — validation (real Handler, nil store)
// Store interaction tested via integration tests.
// ---------------------------------------------------------------------------

func TestMonitorHandler_Create_Validation(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, slog.New(slog.DiscardHandler))

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "missing name returns 400",
			body:       `{"keywords":["go"]}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "malformed JSON returns 400",
			body:       `{not valid json`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "empty body returns 400",
			body:       ``,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/api/admin/tracking", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.Create(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Create() status = %d, want %d (body: %s)", w.Code, tt.wantStatus, w.Body.String())
			}
			eb := decodeMonitorErrorBody(t, w)
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

func TestMonitorHandler_Update_Validation(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, slog.New(slog.DiscardHandler))

	tests := []struct {
		name       string
		pathID     string
		body       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "invalid uuid returns 400",
			pathID:     "not-a-uuid",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "malformed JSON returns 400",
			pathID:     fixedTopicID(t).String(),
			body:       `{bad json`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPut, "/api/admin/tracking/"+tt.pathID, bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()
			h.Update(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Update(%q) status = %d, want %d (body: %s)", tt.pathID, w.Code, tt.wantStatus, w.Body.String())
			}
			eb := decodeMonitorErrorBody(t, w)
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

func TestMonitorHandler_Delete_Validation(t *testing.T) {
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
			pathID:     "bad-uuid",
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodDelete, "/api/admin/tracking/"+tt.pathID, http.NoBody)
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()
			h.Delete(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Delete(%q) status = %d, want %d", tt.pathID, w.Code, tt.wantStatus)
			}
			eb := decodeMonitorErrorBody(t, w)
			if diff := cmp.Diff(tt.wantCode, eb.Error.Code); diff != "" {
				t.Errorf("error code mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
