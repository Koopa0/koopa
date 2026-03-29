package session

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

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
