package session

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// ---------------------------------------------------------------------------
// Stub store
// ---------------------------------------------------------------------------

// stubStore implements noteStore for handler tests with zero real I/O.
type stubStore struct {
	notesByDateFn          func(ctx context.Context, start, end time.Time, noteType *string) ([]Note, error)
	archiveStaleInsightsFn func(ctx context.Context, cutoff time.Time) (int64, error)
	insightsByStatusFn     func(ctx context.Context, status, project *string, limit int32) ([]Note, error)
	countInsightsFn        func(ctx context.Context, status *string) (int64, error)
	noteByIDFn             func(ctx context.Context, id int64) (*Note, error)
	updateNoteMetadataFn   func(ctx context.Context, p *UpdateMetadataParams) (*Note, error)
}

func (s *stubStore) NotesByDate(ctx context.Context, start, end time.Time, noteType *string) ([]Note, error) {
	if s.notesByDateFn != nil {
		return s.notesByDateFn(ctx, start, end, noteType)
	}
	return []Note{}, nil
}

func (s *stubStore) ArchiveStaleInsights(ctx context.Context, cutoff time.Time) (int64, error) {
	if s.archiveStaleInsightsFn != nil {
		return s.archiveStaleInsightsFn(ctx, cutoff)
	}
	return 0, nil
}

func (s *stubStore) InsightsByStatus(ctx context.Context, status, project *string, limit int32) ([]Note, error) {
	if s.insightsByStatusFn != nil {
		return s.insightsByStatusFn(ctx, status, project, limit)
	}
	return []Note{}, nil
}

func (s *stubStore) CountInsightsByStatus(ctx context.Context, status *string) (int64, error) {
	if s.countInsightsFn != nil {
		return s.countInsightsFn(ctx, status)
	}
	return 0, nil
}

func (s *stubStore) NoteByID(ctx context.Context, id int64) (*Note, error) {
	if s.noteByIDFn != nil {
		return s.noteByIDFn(ctx, id)
	}
	return nil, ErrNotFound
}

func (s *stubStore) UpdateNoteMetadata(ctx context.Context, p *UpdateMetadataParams) (*Note, error) {
	if s.updateNoteMetadataFn != nil {
		return s.updateNoteMetadataFn(ctx, p)
	}
	return nil, ErrNotFound
}

// newHandler returns a Handler wired with the given stub and a discard logger.
func newTestHandler(store noteStore) *Handler {
	return &Handler{
		store:  store,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// decodeErrorBody decodes the standard error response envelope.
func decodeErrorBody(t *testing.T, body io.Reader) (code, message string) {
	t.Helper()
	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		t.Fatalf("decodeErrorBody: %v", err)
	}
	return resp.Error.Code, resp.Error.Message
}

// ---------------------------------------------------------------------------
// Unit tests — validateInsightRequest
// ---------------------------------------------------------------------------

func TestValidateInsightRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		req      updateInsightRequest
		wantCode string
	}{
		{
			name:     "all fields empty",
			req:      updateInsightRequest{},
			wantCode: "MISSING_FIELDS",
		},
		{
			name:     "only status present and valid",
			req:      updateInsightRequest{Status: "verified"},
			wantCode: "",
		},
		{
			name:     "only append_evidence present",
			req:      updateInsightRequest{AppendEvidence: "new evidence"},
			wantCode: "",
		},
		{
			name:     "only conclusion present",
			req:      updateInsightRequest{Conclusion: "confirmed"},
			wantCode: "",
		},
		{
			name:     "invalid status enum",
			req:      updateInsightRequest{Status: "pending"},
			wantCode: "INVALID_STATUS",
		},
		{
			name:     "status unverified is valid",
			req:      updateInsightRequest{Status: "unverified"},
			wantCode: "",
		},
		{
			name:     "status invalidated is valid",
			req:      updateInsightRequest{Status: "invalidated"},
			wantCode: "",
		},
		{
			name:     "status archived is valid",
			req:      updateInsightRequest{Status: "archived"},
			wantCode: "",
		},
		{
			name:     "status empty string with evidence — no status validation triggered",
			req:      updateInsightRequest{AppendEvidence: "e", Status: ""},
			wantCode: "",
		},
		{
			name:     "all three fields set",
			req:      updateInsightRequest{Status: "verified", AppendEvidence: "e", Conclusion: "c"},
			wantCode: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotCode, _ := validateInsightRequest(&tt.req)
			if gotCode != tt.wantCode {
				t.Errorf("validateInsightRequest(%+v) code = %q, want %q", tt.req, gotCode, tt.wantCode)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests — applyInsightUpdates
// ---------------------------------------------------------------------------

func TestApplyInsightUpdates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		meta     map[string]any
		req      updateInsightRequest
		wantMeta map[string]any
	}{
		{
			name:     "set status only",
			meta:     map[string]any{},
			req:      updateInsightRequest{Status: "verified"},
			wantMeta: map[string]any{"status": "verified"},
		},
		{
			name:     "append evidence to empty",
			meta:     map[string]any{},
			req:      updateInsightRequest{AppendEvidence: "first evidence"},
			wantMeta: map[string]any{"evidence": []any{"first evidence"}},
		},
		{
			name:     "append evidence to existing",
			meta:     map[string]any{"evidence": []any{"old evidence"}},
			req:      updateInsightRequest{AppendEvidence: "new evidence"},
			wantMeta: map[string]any{"evidence": []any{"old evidence", "new evidence"}},
		},
		{
			name:     "set conclusion",
			meta:     map[string]any{},
			req:      updateInsightRequest{Conclusion: "done"},
			wantMeta: map[string]any{"conclusion": "done"},
		},
		{
			name: "all three fields",
			meta: map[string]any{"evidence": []any{"e1"}},
			req:  updateInsightRequest{Status: "verified", AppendEvidence: "e2", Conclusion: "c"},
			wantMeta: map[string]any{
				"status":     "verified",
				"evidence":   []any{"e1", "e2"},
				"conclusion": "c",
			},
		},
		{
			name:     "empty req does not mutate",
			meta:     map[string]any{"status": "unverified"},
			req:      updateInsightRequest{},
			wantMeta: map[string]any{"status": "unverified"},
		},
		{
			name:     "overwrite existing status",
			meta:     map[string]any{"status": "unverified"},
			req:      updateInsightRequest{Status: "archived"},
			wantMeta: map[string]any{"status": "archived"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			applyInsightUpdates(tt.meta, &tt.req)
			if diff := cmp.Diff(tt.wantMeta, tt.meta); diff != "" {
				t.Errorf("applyInsightUpdates() meta mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests — countEvidence
// ---------------------------------------------------------------------------

func TestCountEvidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  json.RawMessage
		want int
	}{
		{
			name: "nil raw",
			raw:  nil,
			want: 0,
		},
		{
			name: "empty raw",
			raw:  json.RawMessage{},
			want: 0,
		},
		{
			name: "no evidence field",
			raw:  json.RawMessage(`{"status":"unverified"}`),
			want: 0,
		},
		{
			name: "empty evidence array",
			raw:  json.RawMessage(`{"evidence":[]}`),
			want: 0,
		},
		{
			name: "one evidence entry",
			raw:  json.RawMessage(`{"evidence":["first"]}`),
			want: 1,
		},
		{
			name: "three evidence entries",
			raw:  json.RawMessage(`{"evidence":["a","b","c"]}`),
			want: 3,
		},
		{
			name: "invalid json",
			raw:  json.RawMessage(`not-json`),
			want: 0,
		},
		{
			name: "evidence is not an array",
			raw:  json.RawMessage(`{"evidence":"string"}`),
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := countEvidence(tt.raw)
			if got != tt.want {
				t.Errorf("countEvidence(%s) = %d, want %d", tt.raw, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests — parseNoteMetadata
// ---------------------------------------------------------------------------

func TestParseNoteMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     json.RawMessage
		want    map[string]any
		wantErr bool
	}{
		{
			name: "nil raw returns empty map",
			raw:  nil,
			want: map[string]any{},
		},
		{
			name: "empty raw returns empty map",
			raw:  json.RawMessage{},
			want: map[string]any{},
		},
		{
			name: "valid json object",
			raw:  json.RawMessage(`{"status":"unverified","project":"blog"}`),
			want: map[string]any{"status": "unverified", "project": "blog"},
		},
		{
			name:    "invalid json returns error",
			raw:     json.RawMessage(`{bad json`),
			wantErr: true,
		},
		{
			name:    "json array instead of object returns error",
			raw:     json.RawMessage(`["a","b"]`),
			wantErr: true,
		},
		{
			name: "nested object",
			raw:  json.RawMessage(`{"evidence":["e1","e2"],"status":"verified"}`),
			want: map[string]any{
				"evidence": []any{"e1", "e2"},
				"status":   "verified",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseNoteMetadata(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseNoteMetadata(%s) expected error, got nil", tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseNoteMetadata(%s) unexpected error: %v", tt.raw, err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("parseNoteMetadata(%s) mismatch (-want +got):\n%s", tt.raw, diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests — parseInsightNote
// ---------------------------------------------------------------------------

func TestParseInsightNote(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 3, 28, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		note Note
		want insightEntry
	}{
		{
			name: "nil metadata returns defaults",
			note: Note{ID: 1, Content: "insight text", CreatedAt: ts},
			want: insightEntry{
				ID:          1,
				CreatedAt:   "2026-03-28",
				Content:     "insight text",
				Evidence:    []string{},
				Tags:        []string{},
				SourceDates: []string{},
			},
		},
		{
			name: "empty metadata returns defaults",
			note: Note{ID: 2, Content: "x", CreatedAt: ts, Metadata: json.RawMessage(`{}`)},
			want: insightEntry{
				ID:          2,
				CreatedAt:   "2026-03-28",
				Content:     "x",
				Evidence:    []string{},
				Tags:        []string{},
				SourceDates: []string{},
			},
		},
		{
			name: "full metadata populated",
			note: Note{
				ID:        3,
				Content:   "Go value semantics insight",
				CreatedAt: ts,
				Metadata: json.RawMessage(`{
					"hypothesis":   "value types are safer",
					"status":       "verified",
					"evidence":     ["blog post", "talk"],
					"source_dates": ["2026-03-01"],
					"project":      "go-spec",
					"tags":         ["go","design"],
					"conclusion":   "confirmed"
				}`),
			},
			want: insightEntry{
				ID:          3,
				CreatedAt:   "2026-03-28",
				Content:     "Go value semantics insight",
				Hypothesis:  "value types are safer",
				Status:      "verified",
				Evidence:    []string{"blog post", "talk"},
				SourceDates: []string{"2026-03-01"},
				Project:     "go-spec",
				Tags:        []string{"go", "design"},
				Conclusion:  "confirmed",
			},
		},
		{
			name: "invalid metadata returns defaults (no panic)",
			note: Note{ID: 4, Content: "x", CreatedAt: ts, Metadata: json.RawMessage(`not json`)},
			want: insightEntry{
				ID:        4,
				CreatedAt: "2026-03-28",
				Content:   "x",
				Evidence:  []string{},
				Tags:      []string{},
			},
		},
		{
			name: "evidence nil in metadata yields empty slice",
			note: Note{
				ID:        5,
				Content:   "c",
				CreatedAt: ts,
				Metadata:  json.RawMessage(`{"status":"unverified"}`),
			},
			want: insightEntry{
				ID:          5,
				CreatedAt:   "2026-03-28",
				Content:     "c",
				Status:      "unverified",
				Evidence:    []string{},
				Tags:        []string{},
				SourceDates: []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseInsightNote(&tt.note)
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("parseInsightNote() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler tests — List
// ---------------------------------------------------------------------------

func TestHandler_List(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		query      string
		storeNotes []Note
		storeErr   error
		wantStatus int
		wantCode   string // error code, empty on success
	}{
		{
			name:       "default params returns 200",
			query:      "",
			storeNotes: []Note{{ID: 1, NoteType: "plan", Content: "today plan"}},
			wantStatus: http.StatusOK,
		},
		{
			name:       "explicit valid date returns 200",
			query:      "date=2026-03-28&days=3",
			storeNotes: []Note{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid date format returns 400",
			query:      "date=28-03-2026",
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_DATE",
		},
		{
			name:       "date with time component rejected",
			query:      "date=2026-03-28T00:00:00Z",
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_DATE",
		},
		{
			name:       "date as plain integer rejected",
			query:      "date=20260328",
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_DATE",
		},
		{
			name:       "days zero returns 400",
			query:      "days=0",
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_DAYS",
		},
		{
			name:       "days negative returns 400",
			query:      "days=-1",
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_DAYS",
		},
		{
			name:       "days not a number returns 400",
			query:      "days=abc",
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_DAYS",
		},
		{
			name:       "days exceeding 30 is clamped to 30 — still 200",
			query:      "days=999",
			storeNotes: []Note{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid note type returns 400",
			query:      "type=unknown",
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_TYPE",
		},
		{
			name:       "type=plan is valid",
			query:      "type=plan",
			storeNotes: []Note{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "type=reflection is valid",
			query:      "type=reflection",
			storeNotes: []Note{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "type=context is valid",
			query:      "type=context",
			storeNotes: []Note{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "type=metrics is valid",
			query:      "type=metrics",
			storeNotes: []Note{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "type=insight is valid",
			query:      "type=insight",
			storeNotes: []Note{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "store error returns 500",
			query:      "",
			storeErr:   errors.New("db down"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &stubStore{
				notesByDateFn: func(_ context.Context, _, _ time.Time, _ *string) ([]Note, error) {
					return tt.storeNotes, tt.storeErr
				},
			}

			h := newTestHandler(store)
			req := httptest.NewRequest(http.MethodGet, "/api/admin/session-notes?"+tt.query, http.NoBody)
			w := httptest.NewRecorder()
			h.List(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("List(%q) status = %d, want %d\nbody: %s", tt.query, w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantCode != "" {
				code, _ := decodeErrorBody(t, w.Body)
				if code != tt.wantCode {
					t.Errorf("List(%q) error code = %q, want %q", tt.query, code, tt.wantCode)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler tests — Insights
// ---------------------------------------------------------------------------

func TestHandler_Insights(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		query      string
		storeNotes []Note
		storeErr   error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "default params returns 200",
			query:      "",
			storeNotes: []Note{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "explicit status all returns 200",
			query:      "status=all",
			storeNotes: []Note{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "explicit status unverified returns 200",
			query:      "status=unverified",
			storeNotes: []Note{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "limit=1 valid",
			query:      "limit=1",
			storeNotes: []Note{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "limit=100 valid",
			query:      "limit=100",
			storeNotes: []Note{},
			wantStatus: http.StatusOK,
		},
		{
			// limit > 100 is silently clamped (no 400)
			name:       "limit=101 silently uses default",
			query:      "limit=101",
			storeNotes: []Note{},
			wantStatus: http.StatusOK,
		},
		{
			// limit=0 silently uses default
			name:       "limit=0 silently uses default",
			query:      "limit=0",
			storeNotes: []Note{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "store error returns 500",
			query:      "",
			storeErr:   errors.New("db down"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
		{
			name:  "notes with metadata parsed into insight entries",
			query: "",
			storeNotes: []Note{
				{
					ID:        42,
					Content:   "key insight",
					CreatedAt: time.Date(2026, 3, 28, 0, 0, 0, 0, time.UTC),
					NoteType:  "insight",
					Metadata:  json.RawMessage(`{"status":"unverified","evidence":["e1"]}`),
				},
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &stubStore{
				archiveStaleInsightsFn: func(_ context.Context, _ time.Time) (int64, error) {
					return 0, nil
				},
				insightsByStatusFn: func(_ context.Context, _, _ *string, _ int32) ([]Note, error) {
					return tt.storeNotes, tt.storeErr
				},
				countInsightsFn: func(_ context.Context, _ *string) (int64, error) {
					return 0, nil
				},
			}

			h := newTestHandler(store)
			req := httptest.NewRequest(http.MethodGet, "/api/admin/insights?"+tt.query, http.NoBody)
			w := httptest.NewRecorder()
			h.Insights(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Insights(%q) status = %d, want %d\nbody: %s", tt.query, w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantCode != "" {
				code, _ := decodeErrorBody(t, w.Body)
				if code != tt.wantCode {
					t.Errorf("Insights(%q) error code = %q, want %q", tt.query, code, tt.wantCode)
				}
			}
		})
	}
}

// TestHandler_Insights_ResponseShape verifies the data envelope contains the required keys.
func TestHandler_Insights_ResponseShape(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		archiveStaleInsightsFn: func(_ context.Context, _ time.Time) (int64, error) { return 0, nil },
		insightsByStatusFn:     func(_ context.Context, _, _ *string, _ int32) ([]Note, error) { return []Note{}, nil },
		countInsightsFn:        func(_ context.Context, _ *string) (int64, error) { return 7, nil },
	}

	h := newTestHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/api/admin/insights", http.NoBody)
	w := httptest.NewRecorder()
	h.Insights(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Insights() status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp struct {
		Data struct {
			Insights        []any   `json:"insights"`
			Total           float64 `json:"total"`
			UnverifiedCount float64 `json:"unverified_count"`
		} `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Insights() decode error: %v", err)
	}
	// insights must be [] not null for an empty result
	if resp.Data.Insights == nil {
		t.Error("Insights() data.insights = null, want []")
	}
	if resp.Data.UnverifiedCount != 7 {
		t.Errorf("Insights() unverified_count = %v, want 7", resp.Data.UnverifiedCount)
	}
}

// ---------------------------------------------------------------------------
// Handler tests — UpdateInsight
// ---------------------------------------------------------------------------

func TestHandler_UpdateInsight(t *testing.T) {
	t.Parallel()

	baseNote := &Note{
		ID:        1,
		NoteType:  "insight",
		Content:   "original content",
		CreatedAt: time.Date(2026, 3, 28, 0, 0, 0, 0, time.UTC),
		Metadata:  json.RawMessage(`{"status":"unverified","evidence":[]}`),
	}

	tests := []struct {
		name       string
		idPath     string
		body       string
		noteByID   func(ctx context.Context, id int64) (*Note, error)
		updateMeta func(ctx context.Context, p *UpdateMetadataParams) (*Note, error)
		wantStatus int
		wantCode   string
	}{
		{
			name:       "invalid id returns 400",
			idPath:     "notanumber",
			body:       `{"status":"verified"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_ID",
		},
		{
			name:       "missing all fields returns 400",
			idPath:     "1",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "MISSING_FIELDS",
		},
		{
			name:       "invalid status value returns 400",
			idPath:     "1",
			body:       `{"status":"bogus"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_STATUS",
		},
		{
			name:       "malformed json body returns 400",
			idPath:     "1",
			body:       `{not valid json`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_BODY",
		},
		{
			name:   "note not found returns 404",
			idPath: "99",
			body:   `{"status":"verified"}`,
			noteByID: func(_ context.Context, _ int64) (*Note, error) {
				return nil, ErrNotFound
			},
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
		},
		{
			name:   "note is not insight type returns 400",
			idPath: "1",
			body:   `{"status":"verified"}`,
			noteByID: func(_ context.Context, _ int64) (*Note, error) {
				n := *baseNote
				n.NoteType = "plan"
				return &n, nil
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "NOT_INSIGHT",
		},
		{
			name:   "store update error returns 500",
			idPath: "1",
			body:   `{"status":"verified"}`,
			noteByID: func(_ context.Context, _ int64) (*Note, error) {
				return baseNote, nil
			},
			updateMeta: func(_ context.Context, _ *UpdateMetadataParams) (*Note, error) {
				return nil, errors.New("db write failed")
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
		{
			name:   "valid update returns 200",
			idPath: "1",
			body:   `{"status":"verified","append_evidence":"blog post confirmed it"}`,
			noteByID: func(_ context.Context, _ int64) (*Note, error) {
				return baseNote, nil
			},
			updateMeta: func(_ context.Context, p *UpdateMetadataParams) (*Note, error) {
				return &Note{
					ID:       p.ID,
					NoteType: "insight",
					Metadata: p.Metadata,
				}, nil
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "append_evidence only — no status update",
			idPath: "1",
			body:   `{"append_evidence":"new data point"}`,
			noteByID: func(_ context.Context, _ int64) (*Note, error) {
				return baseNote, nil
			},
			updateMeta: func(_ context.Context, p *UpdateMetadataParams) (*Note, error) {
				return &Note{ID: p.ID, NoteType: "insight", Metadata: p.Metadata}, nil
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "empty body returns 400",
			idPath:     "1",
			body:       ``,
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_BODY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			noteByID := tt.noteByID
			if noteByID == nil {
				noteByID = func(_ context.Context, _ int64) (*Note, error) {
					return nil, ErrNotFound
				}
			}
			updateMeta := tt.updateMeta
			if updateMeta == nil {
				updateMeta = func(_ context.Context, _ *UpdateMetadataParams) (*Note, error) {
					return nil, ErrNotFound
				}
			}

			store := &stubStore{
				noteByIDFn:           noteByID,
				updateNoteMetadataFn: updateMeta,
			}

			h := newTestHandler(store)
			req := httptest.NewRequest(http.MethodPut, "/api/admin/insights/"+tt.idPath,
				strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.idPath)
			w := httptest.NewRecorder()
			h.UpdateInsight(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("UpdateInsight(id=%q) status = %d, want %d\nbody: %s",
					tt.idPath, w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantCode != "" {
				code, _ := decodeErrorBody(t, w.Body)
				if code != tt.wantCode {
					t.Errorf("UpdateInsight(id=%q) error code = %q, want %q",
						tt.idPath, code, tt.wantCode)
				}
			}
		})
	}
}

// TestHandler_UpdateInsight_ResponseFields verifies 200 response contains expected top-level keys.
func TestHandler_UpdateInsight_ResponseFields(t *testing.T) {
	t.Parallel()

	meta := json.RawMessage(`{"status":"verified","evidence":["e1","e2"],"conclusion":"confirmed"}`)
	store := &stubStore{
		noteByIDFn: func(_ context.Context, _ int64) (*Note, error) {
			return &Note{ID: 1, NoteType: "insight", Metadata: json.RawMessage(`{"status":"unverified"}`)}, nil
		},
		updateNoteMetadataFn: func(_ context.Context, p *UpdateMetadataParams) (*Note, error) {
			return &Note{ID: p.ID, NoteType: "insight", Metadata: meta}, nil
		},
	}

	h := newTestHandler(store)
	req := httptest.NewRequest(http.MethodPut, "/api/admin/insights/1",
		strings.NewReader(`{"status":"verified","conclusion":"confirmed"}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()
	h.UpdateInsight(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("UpdateInsight() status = %d, want %d\nbody: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp struct {
		Data struct {
			ID            float64 `json:"id"`
			Status        string  `json:"status"`
			EvidenceCount float64 `json:"evidence_count"`
			Conclusion    string  `json:"conclusion"`
			UpdatedAt     string  `json:"updated_at"`
		} `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("UpdateInsight() decode: %v", err)
	}

	if resp.Data.ID != 1 {
		t.Errorf("UpdateInsight() data.id = %v, want 1", resp.Data.ID)
	}
	if resp.Data.Status != "verified" {
		t.Errorf("UpdateInsight() data.status = %q, want %q", resp.Data.Status, "verified")
	}
	if resp.Data.EvidenceCount != 2 {
		t.Errorf("UpdateInsight() data.evidence_count = %v, want 2", resp.Data.EvidenceCount)
	}
	if resp.Data.Conclusion != "confirmed" {
		t.Errorf("UpdateInsight() data.conclusion = %q, want %q", resp.Data.Conclusion, "confirmed")
	}
	if resp.Data.UpdatedAt == "" {
		t.Error("UpdateInsight() data.updated_at is empty")
	}
}

// ---------------------------------------------------------------------------
// Fuzz tests
// ---------------------------------------------------------------------------

func FuzzParseNoteMetadata(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"status":"unverified"}`))
	f.Add([]byte(`{"evidence":["a","b"]}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`["a","b"]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"k":{"nested":true}}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// must not panic
		_, _ = parseNoteMetadata(json.RawMessage(raw))
	})
}

func FuzzCountEvidence(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"evidence":[]}`))
	f.Add([]byte(`{"evidence":["x"]}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"evidence":null}`))
	f.Add([]byte(`{"evidence":{"nested":true}}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// must not panic, must return non-negative value
		got := countEvidence(json.RawMessage(raw))
		if got < 0 {
			t.Errorf("countEvidence(%q) = %d, want >= 0", raw, got)
		}
	})
}

func FuzzParseInsightNote(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"hypothesis":"h","status":"unverified","evidence":["e1"]}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"evidence":123}`))
	f.Add([]byte(`{"tags":null}`))
	f.Add([]byte(`{"source_dates":["2026-01-01"],"project":"p"}`))

	f.Fuzz(func(t *testing.T, rawMeta []byte) {
		note := &Note{
			ID:        1,
			Content:   "fuzz content",
			CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NoteType:  "insight",
			Metadata:  json.RawMessage(rawMeta),
		}

		got := parseInsightNote(note)

		// invariants that must always hold
		if got.ID != note.ID {
			t.Errorf("parseInsightNote() ID = %d, want %d", got.ID, note.ID)
		}
		if got.Content != note.Content {
			t.Errorf("parseInsightNote() Content = %q, want %q", got.Content, note.Content)
		}
		if got.Evidence == nil {
			t.Error("parseInsightNote() Evidence = nil, want non-nil slice")
		}
		if got.Tags == nil {
			t.Error("parseInsightNote() Tags = nil, want non-nil slice")
		}
	})
}
