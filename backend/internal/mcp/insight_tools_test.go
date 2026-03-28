package mcp

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/koopa0/blog-backend/internal/session"
)

// makeInsightNote builds a session.Note for insight tests.
func makeInsightNote(t *testing.T, id int64, content, raw string) session.Note {
	t.Helper()
	n := session.Note{
		ID:        id,
		Content:   content,
		CreatedAt: time.Date(2026, 3, 28, 0, 0, 0, 0, time.UTC),
		NoteType:  "insight",
	}
	if raw != "" {
		n.Metadata = json.RawMessage(raw)
	}
	return n
}

// --- parseInsightNote ---

func TestParseInsightNote(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		note session.Note
		want insightEntry
	}{
		{
			name: "nil metadata returns defaults",
			note: makeInsightNote(t, 1, "content here", ""),
			want: insightEntry{
				ID:                 1,
				CreatedAt:          "2026-03-28",
				Content:            "content here",
				SupportingEvidence: []string{},
				Tags:               []string{},
			},
		},
		{
			name: "current format with supporting_evidence",
			note: makeInsightNote(t, 2, "insight body", `{
				"hypothesis": "Go generics reduce boilerplate",
				"status": "unverified",
				"category": "engineering",
				"supporting_evidence": ["example A", "example B"],
				"source_dates": ["2026-03-01"],
				"tags": ["go", "generics"],
				"project": "blog",
				"conclusion": "",
				"invalidation_condition": "if no code reduction found"
			}`),
			want: insightEntry{
				ID:                    2,
				CreatedAt:             "2026-03-28",
				Content:               "insight body",
				Hypothesis:            "Go generics reduce boilerplate",
				Status:                "unverified",
				Category:              "engineering",
				SupportingEvidence:    []string{"example A", "example B"},
				SourceDates:           []string{"2026-03-01"},
				Tags:                  []string{"go", "generics"},
				Project:               "blog",
				InvalidationCondition: "if no code reduction found",
			},
		},
		{
			name: "legacy evidence field falls back to supporting_evidence",
			note: makeInsightNote(t, 3, "legacy insight", `{
				"evidence": ["legacy item"],
				"status": "verified"
			}`),
			want: insightEntry{
				ID:                 3,
				CreatedAt:          "2026-03-28",
				Content:            "legacy insight",
				Status:             "verified",
				SupportingEvidence: []string{"legacy item"},
				SourceDates:        []string{},
				Tags:               []string{},
			},
		},
		{
			name: "supporting_evidence takes priority over evidence",
			note: makeInsightNote(t, 4, "overlap", `{
				"supporting_evidence": ["new"],
				"evidence": ["old"],
				"status": "unverified"
			}`),
			want: insightEntry{
				ID:                 4,
				CreatedAt:          "2026-03-28",
				Content:            "overlap",
				Status:             "unverified",
				SupportingEvidence: []string{"new"},
				SourceDates:        []string{},
				Tags:               []string{},
			},
		},
		{
			name: "malformed JSON returns defaults",
			note: makeInsightNote(t, 5, "bad meta", `{not valid json`),
			want: insightEntry{
				ID:                 5,
				CreatedAt:          "2026-03-28",
				Content:            "bad meta",
				SupportingEvidence: []string{},
				Tags:               []string{},
			},
		},
		{
			name: "missing optional fields use zero values",
			note: makeInsightNote(t, 6, "minimal", `{"status":"invalidated"}`),
			want: insightEntry{
				ID:                 6,
				CreatedAt:          "2026-03-28",
				Content:            "minimal",
				Status:             "invalidated",
				SupportingEvidence: []string{},
				SourceDates:        []string{},
				Tags:               []string{},
			},
		},
		{
			name: "counter_evidence populated",
			note: makeInsightNote(t, 7, "counter", `{
				"status": "unverified",
				"counter_evidence": ["counter A"]
			}`),
			want: insightEntry{
				ID:                 7,
				CreatedAt:          "2026-03-28",
				Content:            "counter",
				Status:             "unverified",
				SupportingEvidence: []string{},
				CounterEvidence:    []string{"counter A"},
				SourceDates:        []string{},
				Tags:               []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseInsightNote(&tt.note)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("parseInsightNote() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// --- validateInsightInput ---

func TestValidateInsightInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   UpdateInsightInput
		wantErr bool
	}{
		{
			name: "valid with status only",
			input: UpdateInsightInput{
				InsightID: 1,
				Status:    "verified",
			},
		},
		{
			name: "valid with append_evidence only",
			input: UpdateInsightInput{
				InsightID:      1,
				AppendEvidence: "new evidence",
			},
		},
		{
			name: "valid with conclusion only",
			input: UpdateInsightInput{
				InsightID:  1,
				Conclusion: "hypothesis confirmed",
			},
		},
		{
			name: "valid with all fields",
			input: UpdateInsightInput{
				InsightID:             2,
				Status:                "invalidated",
				AppendEvidence:        "ev",
				AppendCounterEvidence: "ce",
				Conclusion:            "done",
			},
		},
		{
			name:    "missing insight_id",
			input:   UpdateInsightInput{Status: "verified"},
			wantErr: true,
		},
		{
			name:    "all update fields empty",
			input:   UpdateInsightInput{InsightID: 1},
			wantErr: true,
		},
		{
			name: "invalid status value",
			input: UpdateInsightInput{
				InsightID: 1,
				Status:    "pending",
			},
			wantErr: true,
		},
		{
			name: "all valid statuses accepted",
			input: UpdateInsightInput{
				InsightID: 1,
				Status:    "archived",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateInsightInput(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("validateInsightInput() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("validateInsightInput() unexpected error: %v", err)
			}
		})
	}
}

// --- parseInsightMetadata ---

func TestParseInsightMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     json.RawMessage
		wantLen int // number of keys expected in result map
		wantErr bool
	}{
		{
			name:    "empty raw message returns empty map",
			raw:     json.RawMessage(nil),
			wantLen: 0,
		},
		{
			name:    "zero-length slice returns empty map",
			raw:     json.RawMessage{},
			wantLen: 0,
		},
		{
			name:    "valid JSON with fields",
			raw:     json.RawMessage(`{"status":"unverified","category":"go"}`),
			wantLen: 2,
		},
		{
			name:    "malformed JSON returns error",
			raw:     json.RawMessage(`{bad`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseInsightMetadata(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseInsightMetadata() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseInsightMetadata() unexpected error: %v", err)
			}
			if len(got) != tt.wantLen {
				t.Errorf("parseInsightMetadata() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

// --- applyInsightUpdates ---

func TestApplyInsightUpdates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		meta  map[string]any
		input UpdateInsightInput
		want  map[string]any
	}{
		{
			name:  "set status on empty meta",
			meta:  map[string]any{},
			input: UpdateInsightInput{InsightID: 1, Status: "verified"},
			want:  map[string]any{"status": "verified"},
		},
		{
			name:  "append evidence to empty list",
			meta:  map[string]any{},
			input: UpdateInsightInput{InsightID: 1, AppendEvidence: "new item"},
			want:  map[string]any{"supporting_evidence": []any{"new item"}},
		},
		{
			name: "append evidence to existing supporting_evidence",
			meta: map[string]any{
				"supporting_evidence": []any{"first"},
			},
			input: UpdateInsightInput{InsightID: 1, AppendEvidence: "second"},
			want: map[string]any{
				"supporting_evidence": []any{"first", "second"},
			},
		},
		{
			name: "legacy evidence migrated to supporting_evidence",
			meta: map[string]any{
				"evidence": []any{"legacy"},
			},
			input: UpdateInsightInput{InsightID: 1, AppendEvidence: "new"},
			want: map[string]any{
				"evidence":            []any{"legacy"},
				"supporting_evidence": []any{"legacy", "new"},
			},
		},
		{
			name:  "append counter_evidence to empty list",
			meta:  map[string]any{},
			input: UpdateInsightInput{InsightID: 1, AppendCounterEvidence: "counter item"},
			want:  map[string]any{"counter_evidence": []any{"counter item"}},
		},
		{
			name:  "set conclusion",
			meta:  map[string]any{},
			input: UpdateInsightInput{InsightID: 1, Conclusion: "confirmed"},
			want:  map[string]any{"conclusion": "confirmed"},
		},
		{
			name:  "no-op when all fields empty",
			meta:  map[string]any{"status": "unverified"},
			input: UpdateInsightInput{InsightID: 1},
			want:  map[string]any{"status": "unverified"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			applyInsightUpdates(tt.meta, tt.input)
			if diff := cmp.Diff(tt.want, tt.meta); diff != "" {
				t.Errorf("applyInsightUpdates() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// --- metaSlice ---

func TestMetaSlice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		meta map[string]any
		key  string
		want []any
	}{
		{
			name: "key with []any value",
			meta: map[string]any{"evidence": []any{"a", "b"}},
			key:  "evidence",
			want: []any{"a", "b"},
		},
		{
			name: "key absent returns nil",
			meta: map[string]any{},
			key:  "evidence",
			want: nil,
		},
		{
			name: "key with wrong type returns nil",
			meta: map[string]any{"evidence": "not a slice"},
			key:  "evidence",
			want: nil,
		},
		{
			name: "nil map returns nil",
			meta: nil,
			key:  "evidence",
			want: nil,
		},
		{
			name: "key with nil value returns nil",
			meta: map[string]any{"evidence": nil},
			key:  "evidence",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := metaSlice(tt.meta, tt.key)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("metaSlice(%q) mismatch (-want +got):\n%s", tt.key, diff)
			}
		})
	}
}

// --- countEvidence ---

func TestCountEvidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  json.RawMessage
		want int
	}{
		{
			name: "nil raw message returns 0",
			raw:  nil,
			want: 0,
		},
		{
			name: "empty raw message returns 0",
			raw:  json.RawMessage{},
			want: 0,
		},
		{
			name: "malformed JSON returns 0",
			raw:  json.RawMessage(`{bad`),
			want: 0,
		},
		{
			name: "no evidence fields returns 0",
			raw:  json.RawMessage(`{"status":"unverified"}`),
			want: 0,
		},
		{
			name: "supporting_evidence with two items",
			raw:  json.RawMessage(`{"supporting_evidence":["a","b"]}`),
			want: 2,
		},
		{
			name: "legacy evidence field",
			raw:  json.RawMessage(`{"evidence":["x","y","z"]}`),
			want: 3,
		},
		{
			name: "supporting_evidence takes priority over evidence",
			raw:  json.RawMessage(`{"supporting_evidence":["a"],"evidence":["b","c"]}`),
			want: 1,
		},
		{
			name: "empty supporting_evidence array returns 0",
			raw:  json.RawMessage(`{"supporting_evidence":[]}`),
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := countEvidence(tt.raw)
			if got != tt.want {
				t.Errorf("countEvidence() = %d, want %d", got, tt.want)
			}
		})
	}
}
