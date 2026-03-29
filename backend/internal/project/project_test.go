package project

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"context"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/koopa0/blog-backend/internal/api"
	"github.com/koopa0/blog-backend/internal/db"
)

// --------------------------------------------------------------------------
// fakeDBTX — minimal db.DBTX stub for store-level error injection.
// --------------------------------------------------------------------------

// fakeRow implements pgx.Row and always returns the configured error.
type fakeRow struct{ err error }

func (r fakeRow) Scan(...any) error { return r.err }

// fakeDBTX implements db.DBTX. Every method returns the configured error.
type fakeDBTX struct{ err error }

func (f *fakeDBTX) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, f.err
}

func (f *fakeDBTX) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return nil, f.err
}

func (f *fakeDBTX) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return fakeRow{err: f.err}
}

// storeWithErr returns a *Store whose every query returns err.
func storeWithErr(err error) *Store {
	return NewStore(&fakeDBTX{err: err})
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// discardLogger returns a logger that discards all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newHandler returns a Handler with the given store and a discarding logger.
func newHandler(s *Store) *Handler {
	return NewHandler(s, discardLogger())
}

// decodeError decodes an api.ErrorBody from the response recorder.
func decodeError(t *testing.T, w *httptest.ResponseRecorder) api.ErrorBody {
	t.Helper()
	var body api.ErrorBody
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decodeError: %v", err)
	}
	return body
}

// assertStatus checks the response code and fatals with the body on mismatch.
func assertStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d, want %d\nbody: %s", w.Code, want, w.Body.String())
	}
}

// --------------------------------------------------------------------------
// Handler.List
// --------------------------------------------------------------------------

func TestHandler_List_StoreError(t *testing.T) {
	t.Parallel()

	h := newHandler(storeWithErr(pgx.ErrTxClosed))
	req := httptest.NewRequest(http.MethodGet, "/api/admin/projects", http.NoBody)
	w := httptest.NewRecorder()

	h.List(w, req)

	assertStatus(t, w, http.StatusInternalServerError)
	errBody := decodeError(t, w)
	if errBody.Error.Code != "INTERNAL" {
		t.Errorf("List() error code = %q, want %q", errBody.Error.Code, "INTERNAL")
	}
}

func TestHandler_List_JSONContentType(t *testing.T) {
	t.Parallel()

	h := newHandler(storeWithErr(pgx.ErrTxClosed))
	req := httptest.NewRequest(http.MethodGet, "/api/admin/projects", http.NoBody)
	w := httptest.NewRecorder()

	h.List(w, req)

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("List() Content-Type = %q, want application/json", ct)
	}
}

// --------------------------------------------------------------------------
// Handler.PublicList
// --------------------------------------------------------------------------

func TestHandler_PublicList_StoreError(t *testing.T) {
	t.Parallel()

	h := newHandler(storeWithErr(pgx.ErrTxClosed))
	req := httptest.NewRequest(http.MethodGet, "/api/projects", http.NoBody)
	w := httptest.NewRecorder()

	h.PublicList(w, req)

	assertStatus(t, w, http.StatusInternalServerError)
	errBody := decodeError(t, w)
	if errBody.Error.Code != "INTERNAL" {
		t.Errorf("PublicList() error code = %q, want %q", errBody.Error.Code, "INTERNAL")
	}
}

// --------------------------------------------------------------------------
// Handler.BySlug
// --------------------------------------------------------------------------

func TestHandler_BySlug(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		slug       string
		storeErr   error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "not found returns 404",
			slug:       "missing",
			storeErr:   ErrNotFound,
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
		},
		{
			name:       "internal error returns 500",
			slug:       "broken",
			storeErr:   pgx.ErrTxClosed,
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHandler(storeWithErr(tt.storeErr))
			req := httptest.NewRequest(http.MethodGet, "/api/projects/"+tt.slug, http.NoBody)
			req.SetPathValue("slug", tt.slug)
			w := httptest.NewRecorder()

			h.BySlug(w, req)

			assertStatus(t, w, tt.wantStatus)
			errBody := decodeError(t, w)
			if errBody.Error.Code != tt.wantCode {
				t.Errorf("BySlug(%q) error code = %q, want %q", tt.slug, errBody.Error.Code, tt.wantCode)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Handler.Create — input validation
// --------------------------------------------------------------------------

func TestHandler_Create_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "malformed JSON returns 400",
			body:       `{not valid json`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "missing slug returns 400",
			body:       `{"title":"My Project","status":"in-progress"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "missing title returns 400",
			body:       `{"slug":"my-project","status":"in-progress"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "empty object returns 400",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// nil store — these tests never reach the store
			h := newHandler(nil)
			req := httptest.NewRequest(http.MethodPost, "/api/admin/projects",
				strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			h.Create(w, req)

			assertStatus(t, w, tt.wantStatus)
			errBody := decodeError(t, w)
			if errBody.Error.Code != tt.wantCode {
				t.Errorf("Create(%q) code = %q, want %q", tt.name, errBody.Error.Code, tt.wantCode)
			}
		})
	}
}

func TestHandler_Create_DefaultStatusReachesStore(t *testing.T) {
	t.Parallel()

	// Omitting status: handler should set StatusInProgress before calling store.
	// We inject ErrConflict so the store is reached (409 proves we passed validation).
	h := newHandler(storeWithErr(ErrConflict))
	req := httptest.NewRequest(http.MethodPost, "/api/admin/projects",
		strings.NewReader(`{"slug":"my-project","title":"My Project"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Create(w, req)

	// 409 proves the store was reached — status was defaulted, validation passed
	assertStatus(t, w, http.StatusConflict)
}

func TestHandler_Create_SlugConflict(t *testing.T) {
	t.Parallel()

	h := newHandler(storeWithErr(ErrConflict))
	req := httptest.NewRequest(http.MethodPost, "/api/admin/projects",
		strings.NewReader(`{"slug":"taken","title":"Taken Project","status":"in-progress"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Create(w, req)

	assertStatus(t, w, http.StatusConflict)
	errBody := decodeError(t, w)
	if errBody.Error.Code != "CONFLICT" {
		t.Errorf("Create() conflict code = %q, want %q", errBody.Error.Code, "CONFLICT")
	}
}

// --------------------------------------------------------------------------
// Handler.Update — input validation and store-error paths
// --------------------------------------------------------------------------

func TestHandler_Update_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		id         string
		body       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "invalid UUID returns 400",
			id:         "not-a-uuid",
			body:       `{"title":"ok"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "malformed JSON returns 400",
			id:         uuid.New().String(),
			body:       `{bad json`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHandler(nil) // never reaches store for invalid UUID
			req := httptest.NewRequest(http.MethodPut, "/api/admin/projects/"+tt.id,
				strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()

			h.Update(w, req)

			assertStatus(t, w, tt.wantStatus)
			errBody := decodeError(t, w)
			if errBody.Error.Code != tt.wantCode {
				t.Errorf("Update(%q) code = %q, want %q", tt.name, errBody.Error.Code, tt.wantCode)
			}
		})
	}
}

func TestHandler_Update_StoreErrors(t *testing.T) {
	t.Parallel()

	id := uuid.New()

	tests := []struct {
		name       string
		storeErr   error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "not found returns 404",
			storeErr:   ErrNotFound,
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
		},
		{
			name:       "slug conflict returns 409",
			storeErr:   ErrConflict,
			wantStatus: http.StatusConflict,
			wantCode:   "CONFLICT",
		},
		{
			name:       "internal error returns 500",
			storeErr:   pgx.ErrTxClosed,
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHandler(storeWithErr(tt.storeErr))
			req := httptest.NewRequest(http.MethodPut, "/api/admin/projects/"+id.String(),
				strings.NewReader(`{"title":"updated"}`))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", id.String())
			w := httptest.NewRecorder()

			h.Update(w, req)

			assertStatus(t, w, tt.wantStatus)
			errBody := decodeError(t, w)
			if errBody.Error.Code != tt.wantCode {
				t.Errorf("Update(%q) code = %q, want %q", tt.name, errBody.Error.Code, tt.wantCode)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Handler.Delete — input validation and store-error paths
// --------------------------------------------------------------------------

func TestHandler_Delete_InvalidUUID(t *testing.T) {
	t.Parallel()

	h := newHandler(nil) // never reaches store
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/projects/bad-id", http.NoBody)
	req.SetPathValue("id", "bad-id")
	w := httptest.NewRecorder()

	h.Delete(w, req)

	assertStatus(t, w, http.StatusBadRequest)
	errBody := decodeError(t, w)
	if errBody.Error.Code != "BAD_REQUEST" {
		t.Errorf("Delete() code = %q, want %q", errBody.Error.Code, "BAD_REQUEST")
	}
}

func TestHandler_Delete_StoreError(t *testing.T) {
	t.Parallel()

	h := newHandler(storeWithErr(pgx.ErrTxClosed))
	id := uuid.New()
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/projects/"+id.String(), http.NoBody)
	req.SetPathValue("id", id.String())
	w := httptest.NewRecorder()

	h.Delete(w, req)

	assertStatus(t, w, http.StatusInternalServerError)
}

// --------------------------------------------------------------------------
// ArchiveOrphanNotion — pure guard logic (no I/O when activeIDs is empty)
// --------------------------------------------------------------------------

func TestStore_ArchiveOrphanNotion_EmptyGuard(t *testing.T) {
	t.Parallel()

	// When activeIDs is empty the method must return (0, nil) without touching
	// the DB. storeWithErr has an always-failing DBTX — any DB access would fail.
	tests := []struct {
		name      string
		activeIDs []string
	}{
		{name: "nil slice", activeIDs: nil},
		{name: "empty slice", activeIDs: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := storeWithErr(pgx.ErrTxClosed)
			n, err := s.ArchiveOrphanNotion(t.Context(), tt.activeIDs)
			if err != nil {
				t.Fatalf("ArchiveOrphanNotion(%v) unexpected error: %v", tt.activeIDs, err)
			}
			if n != 0 {
				t.Errorf("ArchiveOrphanNotion(%v) = %d, want 0", tt.activeIDs, n)
			}
		})
	}
}

// --------------------------------------------------------------------------
// rowToProject — pure data mapping (white-box, no I/O)
// --------------------------------------------------------------------------

func TestRowToProject_FieldMapping(t *testing.T) {
	t.Parallel()

	now := time.Now().Truncate(time.Second)
	goalID := uuid.New()
	deadline := now.Add(24 * time.Hour)
	lastActivity := now.Add(-1 * time.Hour)

	longDesc := "long description"
	problem := "the problem"
	solution := "the solution"
	architecture := "the architecture"
	results := "the results"
	githubURL := "https://github.com/owner/repo"
	liveURL := "https://example.com"
	notionPageID := "notion-abc"
	repo := "owner/repo"
	id := uuid.New()

	row := db.Project{
		ID:              id,
		Slug:            "my-project",
		Title:           "My Project",
		Description:     "desc",
		LongDescription: &longDesc,
		Role:            "lead",
		TechStack:       []string{"Go", "PostgreSQL"},
		Highlights:      []string{"fast", "reliable"},
		Problem:         &problem,
		Solution:        &solution,
		Architecture:    &architecture,
		Results:         &results,
		GithubUrl:       &githubURL,
		LiveUrl:         &liveURL,
		Featured:        true,
		Public:          true,
		SortOrder:       3,
		Status:          db.ProjectStatus(StatusInProgress),
		NotionPageID:    &notionPageID,
		Repo:            &repo,
		Area:            "backend",
		GoalID:          &goalID,
		Deadline:        &deadline,
		LastActivityAt:  &lastActivity,
		ExpectedCadence: "weekly",
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	want := Project{
		ID:              id,
		Slug:            "my-project",
		Title:           "My Project",
		Description:     "desc",
		LongDescription: &longDesc,
		Role:            "lead",
		TechStack:       []string{"Go", "PostgreSQL"},
		Highlights:      []string{"fast", "reliable"},
		Problem:         &problem,
		Solution:        &solution,
		Architecture:    &architecture,
		Results:         &results,
		GithubURL:       &githubURL,
		LiveURL:         &liveURL,
		Featured:        true,
		Public:          true,
		SortOrder:       3,
		Status:          StatusInProgress,
		NotionPageID:    &notionPageID,
		Repo:            &repo,
		Area:            "backend",
		GoalID:          &goalID,
		Deadline:        &deadline,
		LastActivityAt:  &lastActivity,
		ExpectedCadence: "weekly",
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	got := rowToProject(&row)

	opts := cmp.Options{
		cmpopts.EquateApproxTime(time.Second),
	}
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("rowToProject() mismatch (-want +got):\n%s", diff)
	}
}

// --------------------------------------------------------------------------
// Status constants — compile-time guard
// --------------------------------------------------------------------------

func TestStatus_Constants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status Status
		want   string
	}{
		{name: "planned", status: StatusPlanned, want: "planned"},
		{name: "in-progress", status: StatusInProgress, want: "in-progress"},
		{name: "on-hold", status: StatusOnHold, want: "on-hold"},
		{name: "completed", status: StatusCompleted, want: "completed"},
		{name: "maintained", status: StatusMaintained, want: "maintained"},
		{name: "archived", status: StatusArchived, want: "archived"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if string(tt.status) != tt.want {
				t.Errorf("Status(%q) = %q, want %q", tt.name, tt.status, tt.want)
			}
		})
	}
}
