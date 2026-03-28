package mcpserver

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/koopa0/blog-backend/internal/session"
)

// ---------------------------------------------------------------------------
// parseInsightDelta
// ---------------------------------------------------------------------------

func TestParseInsightDelta(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2026, 1, 20, 9, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		note session.Note
		want insightDelta
	}{
		{
			name: "nil metadata returns bare delta with ID",
			note: session.Note{
				ID:       99,
				NoteDate: baseTime,
				Metadata: nil,
			},
			want: insightDelta{ID: 99},
		},
		{
			name: "empty metadata returns bare delta",
			note: session.Note{
				ID:       55,
				NoteDate: baseTime,
				Metadata: json.RawMessage{},
			},
			want: insightDelta{ID: 55},
		},
		{
			name: "malformed JSON returns bare delta",
			note: session.Note{
				ID:       12,
				NoteDate: baseTime,
				Metadata: json.RawMessage(`{not valid json`),
			},
			want: insightDelta{ID: 12},
		},
		{
			name: "full metadata with supporting_evidence",
			note: session.Note{
				ID:       7,
				NoteDate: baseTime,
				Metadata: json.RawMessage(`{
					"hypothesis": "morning sessions are more productive",
					"status": "confirmed",
					"supporting_evidence": ["obs1", "obs2", "obs3"]
				}`),
			},
			want: insightDelta{
				ID:            7,
				Hypothesis:    "morning sessions are more productive",
				CurrentStatus: "confirmed",
				EvidenceCount: 3,
			},
		},
		{
			name: "legacy evidence field used when supporting_evidence is absent",
			note: session.Note{
				ID:       8,
				NoteDate: baseTime,
				Metadata: json.RawMessage(`{
					"hypothesis": "pair programming helps",
					"status": "unverified",
					"evidence": ["obs1", "obs2"]
				}`),
			},
			want: insightDelta{
				ID:            8,
				Hypothesis:    "pair programming helps",
				CurrentStatus: "unverified",
				EvidenceCount: 2,
			},
		},
		{
			name: "supporting_evidence takes priority over legacy evidence when both present",
			note: session.Note{
				ID:       3,
				NoteDate: baseTime,
				Metadata: json.RawMessage(`{
					"hypothesis": "test",
					"status": "unverified",
					"supporting_evidence": ["a", "b", "c"],
					"evidence": ["x", "y"]
				}`),
			},
			want: insightDelta{
				ID:            3,
				Hypothesis:    "test",
				CurrentStatus: "unverified",
				EvidenceCount: 3, // supporting_evidence wins
			},
		},
		{
			name: "empty evidence arrays — count is zero",
			note: session.Note{
				ID:       4,
				NoteDate: baseTime,
				Metadata: json.RawMessage(`{
					"hypothesis": "h",
					"status": "s",
					"supporting_evidence": [],
					"evidence": []
				}`),
			},
			want: insightDelta{
				ID:            4,
				Hypothesis:    "h",
				CurrentStatus: "s",
				EvidenceCount: 0,
			},
		},
		{
			name: "empty JSON object — all fields zero/empty",
			note: session.Note{
				ID:       6,
				NoteDate: baseTime,
				Metadata: json.RawMessage(`{}`),
			},
			want: insightDelta{
				ID:            6,
				EvidenceCount: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseInsightDelta(&tt.note)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("parseInsightDelta() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// FuzzParseInsightDelta ensures parseInsightDelta never panics on arbitrary metadata.
func FuzzParseInsightDelta(f *testing.F) {
	f.Add(`{}`)
	f.Add(`{"hypothesis": "h", "status": "s", "supporting_evidence": ["a"]}`)
	f.Add(`{"supporting_evidence": null, "evidence": null}`)
	f.Add(`not json`)
	f.Add(`{"hypothesis": 42}`) // wrong type

	f.Fuzz(func(t *testing.T, metadata string) {
		n := session.Note{
			ID:       1,
			NoteDate: time.Now(),
			Metadata: json.RawMessage(metadata),
		}
		_ = parseInsightDelta(&n)
	})
}

// ---------------------------------------------------------------------------
// buildDailyMetricsList
// ---------------------------------------------------------------------------

func TestBuildDailyMetricsList(t *testing.T) {
	t.Parallel()

	makeMetricsNote := func(dateStr string, planned, completed int, rate float64) session.Note {
		meta, _ := json.Marshal(map[string]any{
			"tasks_planned":   planned,
			"tasks_completed": completed,
			"completion_rate": rate,
		})
		d, _ := time.Parse(time.DateOnly, dateStr)
		return session.Note{NoteDate: d, Metadata: json.RawMessage(meta)}
	}

	tests := []struct {
		name  string
		notes []session.Note
		wantN int // expected number of entries returned
		check func(t *testing.T, got []dailyMetrics)
	}{
		{
			name:  "nil notes returns empty slice",
			notes: nil,
			wantN: 0,
		},
		{
			name:  "empty notes returns empty slice",
			notes: []session.Note{},
			wantN: 0,
		},
		{
			name: "single parseable note",
			notes: []session.Note{
				makeMetricsNote("2026-03-10", 5, 4, 0.8),
			},
			wantN: 1,
			check: func(t *testing.T, got []dailyMetrics) {
				t.Helper()
				if got[0].Date != "2026-03-10" {
					t.Errorf("entry Date = %q, want %q", got[0].Date, "2026-03-10")
				}
				if got[0].TasksPlanned != 5 {
					t.Errorf("TasksPlanned = %d, want 5", got[0].TasksPlanned)
				}
				if got[0].CompletionRate != 0.8 {
					t.Errorf("CompletionRate = %v, want 0.8", got[0].CompletionRate)
				}
			},
		},
		{
			name: "note with nil metadata is skipped",
			notes: []session.Note{
				{NoteDate: time.Now(), Metadata: nil},
				makeMetricsNote("2026-03-09", 3, 2, 0.67),
			},
			wantN: 1,
		},
		{
			name: "note with malformed JSON is skipped",
			notes: []session.Note{
				{NoteDate: time.Now(), Metadata: json.RawMessage(`{bad json`)},
				makeMetricsNote("2026-03-08", 4, 3, 0.75),
			},
			wantN: 1,
		},
		{
			name: "multiple parseable notes — all returned",
			notes: []session.Note{
				makeMetricsNote("2026-03-10", 5, 4, 0.80),
				makeMetricsNote("2026-03-09", 6, 5, 0.83),
				makeMetricsNote("2026-03-08", 4, 3, 0.75),
			},
			wantN: 3,
			check: func(t *testing.T, got []dailyMetrics) {
				t.Helper()
				// Order must match input order
				dates := []string{"2026-03-10", "2026-03-09", "2026-03-08"}
				for i, want := range dates {
					if got[i].Date != want {
						t.Errorf("entry[%d].Date = %q, want %q", i, got[i].Date, want)
					}
				}
			},
		},
		{
			name: "mixed parseable and unparseable notes",
			notes: []session.Note{
				makeMetricsNote("2026-03-10", 5, 4, 0.8),
				{NoteDate: time.Now(), Metadata: nil},
				makeMetricsNote("2026-03-08", 4, 3, 0.75),
				{NoteDate: time.Now(), Metadata: json.RawMessage(`{bad}`)},
			},
			wantN: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildDailyMetricsList(tt.notes)
			if len(got) != tt.wantN {
				t.Errorf("buildDailyMetricsList() len = %d, want %d", len(got), tt.wantN)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}
