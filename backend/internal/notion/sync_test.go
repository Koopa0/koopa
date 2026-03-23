package notion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/task"
)

// --------------------------------------------------------------------------
// Mock types — defined in test file only, never in production code
// --------------------------------------------------------------------------

type mockProjectWriter struct {
	upsertFn             func(ctx context.Context, p *project.UpsertByNotionParams) (*project.Project, error)
	archiveFn            func(ctx context.Context, notionPageID string) (int64, error)
	archiveOrphanFn      func(ctx context.Context, activeIDs []string) (int64, error)
	updateLastActivityFn func(ctx context.Context, notionPageID string) error
}

func (m *mockProjectWriter) UpsertByNotionPageID(ctx context.Context, p *project.UpsertByNotionParams) (*project.Project, error) {
	if m.upsertFn != nil {
		return m.upsertFn(ctx, p)
	}
	return &project.Project{ID: uuid.New(), Slug: p.Slug, Title: p.Title, Status: p.Status}, nil
}

func (m *mockProjectWriter) ArchiveByNotionPageID(ctx context.Context, notionPageID string) (int64, error) {
	if m.archiveFn != nil {
		return m.archiveFn(ctx, notionPageID)
	}
	return 1, nil
}

func (m *mockProjectWriter) ArchiveOrphanNotion(ctx context.Context, activeIDs []string) (int64, error) {
	if m.archiveOrphanFn != nil {
		return m.archiveOrphanFn(ctx, activeIDs)
	}
	return 0, nil
}

func (m *mockProjectWriter) UpdateLastActivity(ctx context.Context, notionPageID string) error {
	if m.updateLastActivityFn != nil {
		return m.updateLastActivityFn(ctx, notionPageID)
	}
	return nil
}

type mockGoalWriter struct {
	upsertFn        func(ctx context.Context, p *goal.UpsertByNotionParams) (*goal.Goal, error)
	archiveFn       func(ctx context.Context, notionPageID string) (int64, error)
	archiveOrphanFn func(ctx context.Context, activeIDs []string) (int64, error)
}

func (m *mockGoalWriter) UpsertByNotionPageID(ctx context.Context, p *goal.UpsertByNotionParams) (*goal.Goal, error) {
	if m.upsertFn != nil {
		return m.upsertFn(ctx, p)
	}
	return &goal.Goal{ID: uuid.New(), Title: p.Title, Status: p.Status}, nil
}

func (m *mockGoalWriter) ArchiveByNotionPageID(ctx context.Context, notionPageID string) (int64, error) {
	if m.archiveFn != nil {
		return m.archiveFn(ctx, notionPageID)
	}
	return 1, nil
}

func (m *mockGoalWriter) ArchiveOrphanNotion(ctx context.Context, activeIDs []string) (int64, error) {
	if m.archiveOrphanFn != nil {
		return m.archiveOrphanFn(ctx, activeIDs)
	}
	return 0, nil
}

type mockTaskWriter struct {
	upsertFn        func(ctx context.Context, p *task.UpsertByNotionParams) (*task.Task, error)
	archiveFn       func(ctx context.Context, notionPageID string) (int64, error)
	archiveOrphanFn func(ctx context.Context, activeIDs []string) (int64, error)
}

func (m *mockTaskWriter) UpsertByNotionPageID(ctx context.Context, p *task.UpsertByNotionParams) (*task.Task, error) {
	if m.upsertFn != nil {
		return m.upsertFn(ctx, p)
	}
	return &task.Task{ID: uuid.New(), Title: p.Title, Status: p.Status}, nil
}

func (m *mockTaskWriter) ArchiveByNotionPageID(ctx context.Context, notionPageID string) (int64, error) {
	if m.archiveFn != nil {
		return m.archiveFn(ctx, notionPageID)
	}
	return 1, nil
}

func (m *mockTaskWriter) ArchiveOrphanNotion(ctx context.Context, activeIDs []string) (int64, error) {
	if m.archiveOrphanFn != nil {
		return m.archiveOrphanFn(ctx, activeIDs)
	}
	return 0, nil
}

type mockJobSubmitter struct {
	submitFn func(ctx context.Context, flowName string, input json.RawMessage, contentID *uuid.UUID) error
}

func (m *mockJobSubmitter) Submit(ctx context.Context, flowName string, input json.RawMessage, contentID *uuid.UUID) error {
	if m.submitFn != nil {
		return m.submitFn(ctx, flowName, input, contentID)
	}
	return nil
}

// --------------------------------------------------------------------------
// redirectTransport rewrites all request hosts to the given test server URL.
// This allows the real *Client (with its hardcoded notionBaseURL const) to
// speak to a local httptest.Server without modifying production code.
// --------------------------------------------------------------------------

type redirectTransport struct {
	base   http.RoundTripper
	target *url.URL
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	r2.URL.Scheme = t.target.Scheme
	r2.URL.Host = t.target.Host
	return t.base.RoundTrip(r2)
}

// newTestClient returns a *Client that talks to srv instead of api.notion.com.
func newTestClient(srv *httptest.Server) *Client {
	target, _ := url.Parse(srv.URL)
	c := NewClient("test-key")
	c.httpClient = &http.Client{
		Transport: &redirectTransport{
			base:   http.DefaultTransport,
			target: target,
		},
	}
	return c
}

// newTestSourceCache returns a ristretto cache suitable for tests.
// NumCounters is set large enough that TinyLFU reliably admits new items
// even on a cold start (TinyLFU needs warm-up; over-provisioning avoids flakiness).
func newTestSourceCache(t *testing.T) *ristretto.Cache[string, string] {
	t.Helper()
	cache, err := ristretto.NewCache(&ristretto.Config[string, string]{
		NumCounters: 10_000, // 10× expected items for TinyLFU warmth
		MaxCost:     1_000,
		BufferItems: 64,
		// IgnoreInternalCost removes per-key overhead so cost=1 is reliable.
		IgnoreInternalCost: true,
	})
	if err != nil {
		t.Fatalf("creating test source cache: %v", err)
	}
	t.Cleanup(cache.Close)
	return cache
}

// notionPageJSON builds a minimal Notion page JSON response for test servers.
func notionPageJSON(id string, inTrash, archived bool, props map[string]string) string { //nolint:unparam // test helper designed for varied page IDs
	type titleItem struct {
		PlainText string `json:"plain_text"`
	}
	type titleProp struct {
		Title []titleItem `json:"title"`
	}
	type statusName struct {
		Name string `json:"name"`
	}
	type statusProp struct {
		Status *statusName `json:"status"`
	}

	propMap := map[string]any{}
	if name, ok := props["Name"]; ok {
		propMap["Name"] = titleProp{Title: []titleItem{{PlainText: name}}}
	}
	if name, ok := props["Task Name"]; ok {
		propMap["Task Name"] = titleProp{Title: []titleItem{{PlainText: name}}}
	}
	if s, ok := props["Status"]; ok {
		propMap["Status"] = statusProp{Status: &statusName{Name: s}}
	}
	if s, ok := props["Title"]; ok {
		propMap["Title"] = titleProp{Title: []titleItem{{PlainText: s}}}
	}

	rawProps := map[string]json.RawMessage{}
	for k, v := range propMap {
		b, _ := json.Marshal(v)
		rawProps[k] = b
	}

	type pageResp struct {
		ID         string                     `json:"id"`
		Archived   bool                       `json:"archived"`
		InTrash    bool                       `json:"in_trash"`
		Properties map[string]json.RawMessage `json:"properties"`
	}

	b, _ := json.Marshal(pageResp{
		ID:         id,
		Archived:   archived,
		InTrash:    inTrash,
		Properties: rawProps,
	})
	return string(b)
}

// validPageIDForTest is a well-formed UUID suitable for use as a Notion page ID.
const validPageIDForTest = "12345678-1234-1234-1234-123456789abc"

// --------------------------------------------------------------------------
// buildSourceID
// --------------------------------------------------------------------------

func TestBuildSourceID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		pageID string
		status string
		want   string
	}{
		{
			name:   "basic",
			pageID: "abc",
			status: "done",
			want:   "abc:done",
		},
		{
			name:   "same page different status",
			pageID: "abc",
			status: "in-progress",
			want:   "abc:in-progress",
		},
		{
			name:   "uuid page id",
			pageID: validPageIDForTest,
			status: "planned",
			want:   validPageIDForTest + ":planned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildSourceID(tt.pageID, tt.status)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("buildSourceID(%q, %q) mismatch (-want +got):\n%s", tt.pageID, tt.status, diff)
			}
		})
	}
}

// --------------------------------------------------------------------------
// validPageID
// --------------------------------------------------------------------------

func TestValidPageID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid uuid lowercase",
			input: "12345678-abcd-abcd-abcd-123456789abc",
			want:  true,
		},
		{
			name:  "valid uuid uppercase",
			input: "12345678-ABCD-ABCD-ABCD-123456789ABC",
			want:  true,
		},
		{
			name:  "valid uuid mixed case",
			input: "12345678-1234-1234-1234-123456789abc",
			want:  true,
		},
		{
			name:  "too short",
			input: "12345678-1234-1234-1234-12345678abc",
			want:  false,
		},
		{
			name:  "too long",
			input: "12345678-1234-1234-1234-123456789abcd",
			want:  false,
		},
		{
			name:  "missing dashes",
			input: "123456781234123412341234567890ab",
			want:  false,
		},
		{
			name:  "path traversal",
			input: "../etc/pa-sswd-0000-0000-000000000000",
			want:  false,
		},
		{
			name:  "query string injection",
			input: "12345678-1234-1234-1234-12345678?abc",
			want:  false,
		},
		{
			name:  "null bytes",
			input: "12345678-1234-1234-1234-12345678\x00bc",
			want:  false,
		},
		{
			name:  "dash at wrong position",
			input: "1234567-81234-1234-1234-123456789abc",
			want:  false,
		},
		{
			name:  "invalid hex char",
			input: "12345678-1234-1234-1234-12345678gggg",
			want:  false,
		},
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := validPageID(tt.input)
			if got != tt.want {
				t.Errorf("validPageID(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// upsertProject
// --------------------------------------------------------------------------

func TestUpsertProject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		props       map[string]json.RawMessage
		pageID      string
		upsertFn    func(ctx context.Context, p *project.UpsertByNotionParams) (*project.Project, error)
		wantErr     bool
		wantStatus  project.Status
		wantSlugPfx string // slug must start with this prefix
	}{
		{
			name:   "happy path planned",
			pageID: validPageIDForTest,
			props: map[string]json.RawMessage{
				"Name":   mustMarshalTitle("My Project"),
				"Status": mustMarshalStatus("Planned"),
			},
			wantErr:     false,
			wantStatus:  project.StatusPlanned,
			wantSlugPfx: "my-project-",
		},
		{
			name:   "status doing maps to in-progress",
			pageID: validPageIDForTest,
			props: map[string]json.RawMessage{
				"Name":   mustMarshalTitle("Active Work"),
				"Status": mustMarshalStatus("Doing"),
			},
			wantStatus: project.StatusInProgress,
		},
		{
			name:   "status on hold",
			pageID: validPageIDForTest,
			props: map[string]json.RawMessage{
				"Name":   mustMarshalTitle("Paused"),
				"Status": mustMarshalStatus("On Hold"),
			},
			wantStatus: project.StatusOnHold,
		},
		{
			name:   "status ongoing maps to maintained",
			pageID: validPageIDForTest,
			props: map[string]json.RawMessage{
				"Name":   mustMarshalTitle("Maintained"),
				"Status": mustMarshalStatus("Ongoing"),
			},
			wantStatus: project.StatusMaintained,
		},
		{
			name:   "status done maps to completed",
			pageID: validPageIDForTest,
			props: map[string]json.RawMessage{
				"Name":   mustMarshalTitle("Finished"),
				"Status": mustMarshalStatus("Done"),
			},
			wantStatus: project.StatusCompleted,
		},
		{
			name:   "empty title returns error",
			pageID: validPageIDForTest,
			props: map[string]json.RawMessage{
				"Name":   mustMarshalTitle(""),
				"Status": mustMarshalStatus("Doing"),
			},
			wantErr: true,
		},
		{
			name:   "missing name property returns error",
			pageID: validPageIDForTest,
			props: map[string]json.RawMessage{
				"Status": mustMarshalStatus("Doing"),
			},
			wantErr: true,
		},
		{
			name:   "upsert error propagated",
			pageID: validPageIDForTest,
			props: map[string]json.RawMessage{
				"Name":   mustMarshalTitle("Something"),
				"Status": mustMarshalStatus("Doing"),
			},
			upsertFn: func(_ context.Context, _ *project.UpsertByNotionParams) (*project.Project, error) {
				return nil, errors.New("db unavailable")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pw := &mockProjectWriter{}
			var capturedParams project.UpsertByNotionParams
			if tt.upsertFn != nil {
				pw.upsertFn = tt.upsertFn
			} else {
				pw.upsertFn = func(_ context.Context, p *project.UpsertByNotionParams) (*project.Project, error) {
					capturedParams = *p
					return &project.Project{ID: uuid.New(), Slug: p.Slug, Title: p.Title, Status: p.Status}, nil
				}
			}

			h := &Handler{
				projects: pw,
				logger:   slog.Default(),
			}

			err := h.upsertProject(t.Context(), tt.pageID, tt.props)

			if tt.wantErr {
				if err == nil {
					t.Fatal("upsertProject() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("upsertProject() unexpected error: %v", err)
			}

			if tt.wantStatus != "" && capturedParams.Status != tt.wantStatus {
				t.Errorf("upsertProject() status = %q, want %q", capturedParams.Status, tt.wantStatus)
			}

			if tt.wantSlugPfx != "" && !strings.HasPrefix(capturedParams.Slug, tt.wantSlugPfx) {
				t.Errorf("upsertProject() slug = %q, want prefix %q", capturedParams.Slug, tt.wantSlugPfx)
			}
		})
	}
}

// --------------------------------------------------------------------------
// syncProject (webhook path — uses h.client.Page)
// --------------------------------------------------------------------------

func TestSyncProject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		notionResp   string
		notionStatus int
		upsertFn     func(ctx context.Context, p *project.UpsertByNotionParams) (*project.Project, error)
		archiveFn    func(ctx context.Context, notionPageID string) (int64, error)
		wantErr      bool
		wantErrIs    error
		wantArchived bool
	}{
		{
			name:         "happy path",
			notionResp:   notionPageJSON(validPageIDForTest, false, false, map[string]string{"Name": "My Project", "Status": "Doing"}),
			notionStatus: http.StatusOK,
			wantErr:      false,
		},
		{
			name:         "trashed page returns ErrSkipped and archives",
			notionResp:   notionPageJSON(validPageIDForTest, true, false, map[string]string{"Name": "Trashed", "Status": "Doing"}),
			notionStatus: http.StatusOK,
			wantErr:      true,
			wantErrIs:    ErrSkipped,
			wantArchived: true,
		},
		{
			name:         "archived page returns ErrSkipped and archives",
			notionResp:   notionPageJSON(validPageIDForTest, false, true, map[string]string{"Name": "Archived", "Status": "Doing"}),
			notionStatus: http.StatusOK,
			wantErr:      true,
			wantErrIs:    ErrSkipped,
			wantArchived: true,
		},
		{
			name:         "archive failure returns real error not ErrSkipped",
			notionResp:   notionPageJSON(validPageIDForTest, true, false, map[string]string{"Name": "Trashed", "Status": "Doing"}),
			notionStatus: http.StatusOK,
			archiveFn: func(_ context.Context, _ string) (int64, error) {
				return 0, errors.New("archive store error")
			},
			wantErr:   true,
			wantErrIs: nil, // must NOT be ErrSkipped
		},
		{
			name:         "notion API error propagated",
			notionStatus: http.StatusInternalServerError,
			notionResp:   `{"message":"internal error"}`,
			wantErr:      true,
		},
		{
			name:         "empty title returns error",
			notionResp:   notionPageJSON(validPageIDForTest, false, false, map[string]string{"Name": "", "Status": "Doing"}),
			notionStatus: http.StatusOK,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.notionStatus)
				_, _ = fmt.Fprint(w, tt.notionResp)
			}))
			t.Cleanup(srv.Close)

			archived := false
			pw := &mockProjectWriter{
				archiveFn: func(_ context.Context, _ string) (int64, error) {
					archived = true
					if tt.archiveFn != nil {
						return tt.archiveFn(nil, "")
					}
					return 1, nil
				},
			}
			if tt.archiveFn != nil {
				pw.archiveFn = func(ctx context.Context, notionPageID string) (int64, error) {
					archived = true
					return tt.archiveFn(ctx, notionPageID)
				}
			}

			h := &Handler{
				client:   newTestClient(srv),
				projects: pw,
				logger:   slog.Default(),
			}

			err := h.syncProject(t.Context(), validPageIDForTest)

			if tt.wantErr {
				if err == nil {
					t.Fatal("syncProject() expected error, got nil")
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Errorf("syncProject() error = %v, want errors.Is(%v)", err, tt.wantErrIs)
				}
				if tt.wantErrIs == nil && tt.wantArchived {
					// archive failure case: error must NOT be ErrSkipped
					if errors.Is(err, ErrSkipped) {
						t.Errorf("syncProject() archive failure: error should not be ErrSkipped, got %v", err)
					}
				}
			} else if err != nil {
				t.Fatalf("syncProject() unexpected error: %v", err)
			}

			if tt.wantArchived && !archived {
				t.Error("syncProject() expected ArchiveByNotionPageID to be called")
			}
		})
	}
}

// --------------------------------------------------------------------------
// syncGoal (webhook path)
// --------------------------------------------------------------------------

func TestSyncGoal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		notionResp   string
		notionStatus int
		archiveFn    func(ctx context.Context, notionPageID string) (int64, error)
		wantErr      bool
		wantErrIs    error
		wantArchived bool
	}{
		{
			name:         "happy path not started",
			notionResp:   notionPageJSON(validPageIDForTest, false, false, map[string]string{"Name": "Q1 Goal", "Status": "Not Started"}),
			notionStatus: http.StatusOK,
			wantErr:      false,
		},
		{
			name:         "trashed page returns ErrSkipped and archives",
			notionResp:   notionPageJSON(validPageIDForTest, true, false, map[string]string{"Name": "Old Goal", "Status": "Done"}),
			notionStatus: http.StatusOK,
			wantErr:      true,
			wantErrIs:    ErrSkipped,
			wantArchived: true,
		},
		{
			name:         "archived page returns ErrSkipped and archives",
			notionResp:   notionPageJSON(validPageIDForTest, false, true, map[string]string{"Name": "Old Goal", "Status": "Done"}),
			notionStatus: http.StatusOK,
			wantErr:      true,
			wantErrIs:    ErrSkipped,
			wantArchived: true,
		},
		{
			name:         "archive failure returns real error not ErrSkipped",
			notionResp:   notionPageJSON(validPageIDForTest, true, false, map[string]string{"Name": "Old Goal", "Status": "Done"}),
			notionStatus: http.StatusOK,
			archiveFn: func(_ context.Context, _ string) (int64, error) {
				return 0, errors.New("archive db error")
			},
			wantErr:      true,
			wantArchived: true,
		},
		{
			name:         "empty title returns error",
			notionResp:   notionPageJSON(validPageIDForTest, false, false, map[string]string{"Name": "", "Status": "Doing"}),
			notionStatus: http.StatusOK,
			wantErr:      true,
		},
		{
			name:         "notion API error propagated",
			notionStatus: http.StatusNotFound,
			notionResp:   `{"message":"not found"}`,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.notionStatus)
				_, _ = fmt.Fprint(w, tt.notionResp)
			}))
			t.Cleanup(srv.Close)

			archived := false
			gw := &mockGoalWriter{}
			if tt.archiveFn != nil {
				gw.archiveFn = func(ctx context.Context, notionPageID string) (int64, error) {
					archived = true
					return tt.archiveFn(ctx, notionPageID)
				}
			} else {
				gw.archiveFn = func(_ context.Context, _ string) (int64, error) {
					archived = true
					return 1, nil
				}
			}

			h := &Handler{
				client: newTestClient(srv),
				goals:  gw,
				logger: slog.Default(),
			}

			err := h.syncGoal(t.Context(), validPageIDForTest)

			if tt.wantErr {
				if err == nil {
					t.Fatal("syncGoal() expected error, got nil")
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Errorf("syncGoal() error = %v, want errors.Is(%v)", err, tt.wantErrIs)
				}
				if tt.archiveFn != nil && errors.Is(err, ErrSkipped) {
					t.Errorf("syncGoal() archive failure should not return ErrSkipped, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("syncGoal() unexpected error: %v", err)
			}

			if tt.wantArchived && !archived {
				t.Error("syncGoal() expected ArchiveByNotionPageID to be called")
			}
		})
	}
}

// --------------------------------------------------------------------------
// syncTask (webhook path)
// --------------------------------------------------------------------------

func TestSyncTask(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		notionResp   string
		notionStatus int
		archiveFn    func(ctx context.Context, notionPageID string) (int64, error)
		wantErr      bool
		wantErrIs    error
		wantArchived bool
	}{
		{
			name:         "happy path todo",
			notionResp:   notionPageJSON(validPageIDForTest, false, false, map[string]string{"Task Name": "Fix bug", "Status": "To Do"}),
			notionStatus: http.StatusOK,
			wantErr:      false,
		},
		{
			name:         "trashed page returns ErrSkipped and archives",
			notionResp:   notionPageJSON(validPageIDForTest, true, false, map[string]string{"Task Name": "Old Task", "Status": "Done"}),
			notionStatus: http.StatusOK,
			wantErr:      true,
			wantErrIs:    ErrSkipped,
			wantArchived: true,
		},
		{
			name:         "archived page returns ErrSkipped and archives",
			notionResp:   notionPageJSON(validPageIDForTest, false, true, map[string]string{"Task Name": "Old Task", "Status": "Done"}),
			notionStatus: http.StatusOK,
			wantErr:      true,
			wantErrIs:    ErrSkipped,
			wantArchived: true,
		},
		{
			name:         "archive failure returns real error not ErrSkipped",
			notionResp:   notionPageJSON(validPageIDForTest, true, false, map[string]string{"Task Name": "Old Task", "Status": "Done"}),
			notionStatus: http.StatusOK,
			archiveFn: func(_ context.Context, _ string) (int64, error) {
				return 0, errors.New("db failure")
			},
			wantErr:      true,
			wantArchived: true,
		},
		{
			name:         "notion API error propagated",
			notionStatus: http.StatusBadGateway,
			notionResp:   `{"message":"gateway error"}`,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.notionStatus)
				_, _ = fmt.Fprint(w, tt.notionResp)
			}))
			t.Cleanup(srv.Close)

			archived := false
			tw := &mockTaskWriter{}
			if tt.archiveFn != nil {
				tw.archiveFn = func(ctx context.Context, notionPageID string) (int64, error) {
					archived = true
					return tt.archiveFn(ctx, notionPageID)
				}
			} else {
				tw.archiveFn = func(_ context.Context, _ string) (int64, error) {
					archived = true
					return 1, nil
				}
			}

			h := &Handler{
				client: newTestClient(srv),
				tasks:  tw,
				logger: slog.Default(),
			}

			err := h.syncTask(t.Context(), validPageIDForTest)

			if tt.wantErr {
				if err == nil {
					t.Fatal("syncTask() expected error, got nil")
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Errorf("syncTask() error = %v, want errors.Is(%v)", err, tt.wantErrIs)
				}
				if tt.archiveFn != nil && errors.Is(err, ErrSkipped) {
					t.Errorf("syncTask() archive failure should not return ErrSkipped, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("syncTask() unexpected error: %v", err)
			}

			if tt.wantArchived && !archived {
				t.Error("syncTask() expected ArchiveByNotionPageID to be called")
			}
		})
	}
}

// --------------------------------------------------------------------------
// syncBook (webhook path)
// --------------------------------------------------------------------------

func TestSyncBook(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		notionResp    string
		notionStatus  int
		wantErr       bool
		wantErrIs     error
		wantSubmitted bool
		submitFn      func(ctx context.Context, flowName string, input json.RawMessage, contentID *uuid.UUID) error
	}{
		{
			name:          "book with Read status submits bookmark-generate",
			notionResp:    notionPageJSON(validPageIDForTest, false, false, map[string]string{"Title": "Deep Work", "Status": "Read"}),
			notionStatus:  http.StatusOK,
			wantErr:       false,
			wantSubmitted: true,
		},
		{
			name:         "book with non-Read status skips submission",
			notionResp:   notionPageJSON(validPageIDForTest, false, false, map[string]string{"Title": "Reading Now", "Status": "In Progress"}),
			notionStatus: http.StatusOK,
			wantErr:      false,
			// not submitted: status != "Read"
		},
		{
			name:         "trashed book returns ErrSkipped without archiving",
			notionResp:   notionPageJSON(validPageIDForTest, true, false, map[string]string{"Title": "Old Book", "Status": "Read"}),
			notionStatus: http.StatusOK,
			wantErr:      true,
			wantErrIs:    ErrSkipped,
		},
		{
			name:         "archived book returns ErrSkipped without archiving",
			notionResp:   notionPageJSON(validPageIDForTest, false, true, map[string]string{"Title": "Old Book", "Status": "Read"}),
			notionStatus: http.StatusOK,
			wantErr:      true,
			wantErrIs:    ErrSkipped,
		},
		{
			name:         "notion API error propagated",
			notionStatus: http.StatusInternalServerError,
			notionResp:   `{"message":"error"}`,
			wantErr:      true,
		},
		{
			name:         "submit error propagated",
			notionResp:   notionPageJSON(validPageIDForTest, false, false, map[string]string{"Title": "Good Book", "Status": "Read"}),
			notionStatus: http.StatusOK,
			submitFn: func(_ context.Context, _ string, _ json.RawMessage, _ *uuid.UUID) error {
				return errors.New("job queue unavailable")
			},
			wantErr:       true,
			wantSubmitted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.notionStatus)
				_, _ = fmt.Fprint(w, tt.notionResp)
			}))
			t.Cleanup(srv.Close)

			submitted := false
			jm := &mockJobSubmitter{
				submitFn: func(ctx context.Context, flowName string, input json.RawMessage, contentID *uuid.UUID) error {
					submitted = true
					if tt.submitFn != nil {
						return tt.submitFn(ctx, flowName, input, contentID)
					}
					return nil
				},
			}

			h := &Handler{
				client: newTestClient(srv),
				jobs:   jm,
				logger: slog.Default(),
			}

			err := h.syncBook(t.Context(), validPageIDForTest)

			if tt.wantErr {
				if err == nil {
					t.Fatal("syncBook() expected error, got nil")
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Errorf("syncBook() error = %v, want errors.Is(%v)", err, tt.wantErrIs)
				}
			} else if err != nil {
				t.Fatalf("syncBook() unexpected error: %v", err)
			}

			if tt.wantSubmitted && !submitted {
				t.Error("syncBook() expected jobs.Submit to be called")
			}
			if !tt.wantSubmitted && submitted {
				t.Error("syncBook() unexpected jobs.Submit call")
			}
		})
	}
}

// --------------------------------------------------------------------------
// upsertGoal — status mapping coverage
// --------------------------------------------------------------------------

func TestUpsertGoalStatusMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		notionStatus string
		wantStatus   goal.Status
	}{
		{name: "not started", notionStatus: "Not Started", wantStatus: goal.StatusNotStarted},
		{name: "in progress", notionStatus: "In Progress", wantStatus: goal.StatusInProgress},
		{name: "doing", notionStatus: "Doing", wantStatus: goal.StatusInProgress},
		{name: "done", notionStatus: "Done", wantStatus: goal.StatusDone},
		{name: "abandoned", notionStatus: "Abandoned", wantStatus: goal.StatusAbandoned},
		{name: "unknown defaults to not-started", notionStatus: "SomeOther", wantStatus: goal.StatusNotStarted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var capturedStatus goal.Status
			gw := &mockGoalWriter{
				upsertFn: func(_ context.Context, p *goal.UpsertByNotionParams) (*goal.Goal, error) {
					capturedStatus = p.Status
					return &goal.Goal{ID: uuid.New(), Title: p.Title, Status: p.Status}, nil
				},
			}

			h := &Handler{
				goals:  gw,
				logger: slog.Default(),
			}

			props := map[string]json.RawMessage{
				"Name":   mustMarshalTitle("Test Goal"),
				"Status": mustMarshalStatus(tt.notionStatus),
			}

			err := h.upsertGoal(t.Context(), validPageIDForTest, props)
			if err != nil {
				t.Fatalf("upsertGoal() unexpected error: %v", err)
			}

			if capturedStatus != tt.wantStatus {
				t.Errorf("upsertGoal() status = %q, want %q", capturedStatus, tt.wantStatus)
			}
		})
	}
}

// --------------------------------------------------------------------------
// upsertTask — status mapping coverage
// --------------------------------------------------------------------------

func TestUpsertTaskStatusMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		notionStatus string
		wantStatus   task.Status
	}{
		{name: "not started", notionStatus: "Not Started", wantStatus: task.StatusTodo},
		{name: "to do", notionStatus: "To Do", wantStatus: task.StatusTodo},
		{name: "in progress", notionStatus: "In Progress", wantStatus: task.StatusInProgress},
		{name: "doing", notionStatus: "Doing", wantStatus: task.StatusInProgress},
		{name: "done", notionStatus: "Done", wantStatus: task.StatusDone},
		{name: "unknown defaults to todo", notionStatus: "SomeOther", wantStatus: task.StatusTodo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var capturedStatus task.Status
			tw := &mockTaskWriter{
				upsertFn: func(_ context.Context, p *task.UpsertByNotionParams) (*task.Task, error) {
					capturedStatus = p.Status
					return &task.Task{ID: uuid.New(), Title: p.Title, Status: p.Status}, nil
				},
			}

			h := &Handler{
				tasks:  tw,
				logger: slog.Default(),
			}

			props := map[string]json.RawMessage{
				"Task Name": mustMarshalTitle("Test Task"),
				"Status":    mustMarshalStatus(tt.notionStatus),
			}

			err := h.upsertTask(t.Context(), validPageIDForTest, props)
			if err != nil {
				t.Fatalf("upsertTask() unexpected error: %v", err)
			}

			if capturedStatus != tt.wantStatus {
				t.Errorf("upsertTask() status = %q, want %q", capturedStatus, tt.wantStatus)
			}
		})
	}
}

// --------------------------------------------------------------------------
// upsertTask — uses "Name" as fallback when "Task Name" is empty
// --------------------------------------------------------------------------

func TestUpsertTaskTitleFallback(t *testing.T) {
	t.Parallel()

	var capturedTitle string
	tw := &mockTaskWriter{
		upsertFn: func(_ context.Context, p *task.UpsertByNotionParams) (*task.Task, error) {
			capturedTitle = p.Title
			return &task.Task{ID: uuid.New(), Title: p.Title, Status: p.Status}, nil
		},
	}

	h := &Handler{
		tasks:  tw,
		logger: slog.Default(),
	}

	props := map[string]json.RawMessage{
		"Task Name": mustMarshalTitle(""),
		"Name":      mustMarshalTitle("Fallback Title"),
		"Status":    mustMarshalStatus("Done"),
	}

	if err := h.upsertTask(t.Context(), validPageIDForTest, props); err != nil {
		t.Fatalf("upsertTask() unexpected error: %v", err)
	}

	if capturedTitle != "Fallback Title" {
		t.Errorf("upsertTask() title = %q, want %q", capturedTitle, "Fallback Title")
	}
}

// --------------------------------------------------------------------------
// upsertGoal — empty title returns error
// --------------------------------------------------------------------------

func TestUpsertGoalEmptyTitle(t *testing.T) {
	t.Parallel()

	h := &Handler{
		goals:  &mockGoalWriter{},
		logger: slog.Default(),
	}

	props := map[string]json.RawMessage{
		"Name":   mustMarshalTitle(""),
		"Status": mustMarshalStatus("Doing"),
	}

	err := h.upsertGoal(t.Context(), validPageIDForTest, props)
	if err == nil {
		t.Fatal("upsertGoal() expected error for empty title, got nil")
	}
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// mustMarshalTitle returns a json.RawMessage for a Notion title property.
func mustMarshalTitle(text string) json.RawMessage {
	v := map[string]any{
		"title": []map[string]string{
			{"plain_text": text},
		},
	}
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("mustMarshalTitle: %v", err))
	}
	return b
}

// mustMarshalStatus returns a json.RawMessage for a Notion status property.
func mustMarshalStatus(name string) json.RawMessage {
	v := map[string]any{
		"status": map[string]string{"name": name},
	}
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("mustMarshalStatus: %v", err))
	}
	return b
}
