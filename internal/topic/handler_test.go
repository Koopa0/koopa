// Copyright 2026 Koopa. All rights reserved.

package topic

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
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

// ---------------------------------------------------------------------------
// publishedOnly — the public /api/topics filter that hides empty categories.
// Pure function, so it is tested directly (the cache/store path is best-effort
// and covered by integration tests).
// ---------------------------------------------------------------------------

func TestPublishedOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []Topic
		want []string // slugs, in order
	}{
		{
			name: "hides zero-content topics, keeps the rest in order",
			in: []Topic{
				{Slug: "go", ContentCount: 3},
				{Slug: "rust", ContentCount: 0},
				{Slug: "security", ContentCount: 1},
			},
			want: []string{"go", "security"},
		},
		{
			name: "all empty yields an empty (non-nil) slice",
			in: []Topic{
				{Slug: "go", ContentCount: 0},
				{Slug: "rust", ContentCount: 0},
			},
			want: []string{},
		},
		{
			name: "nil input yields an empty (non-nil) slice",
			in:   nil,
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := publishedOnly(tt.in)
			if got == nil {
				t.Fatal("publishedOnly returned nil; want non-nil slice for JSON []")
			}
			gotSlugs := make([]string, len(got))
			for i, topic := range got {
				gotSlugs[i] = topic.Slug
			}
			if diff := cmp.Diff(tt.want, gotSlugs); diff != "" {
				t.Errorf("publishedOnly() slugs mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Handler.List, Handler.ListPublished, Handler.BySlug, and store-interaction
// paths for Create/Update/Delete are tested via integration tests (require a
// real database connection).
