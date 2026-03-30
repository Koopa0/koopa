package mcp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/Koopa0/koopa0.dev/internal/session"
)

// ---------------------------------------------------------------------------
// buildSectionSet
// ---------------------------------------------------------------------------

func TestBuildSectionSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sections []string
		want     map[string]bool // nil means "expect nil return"
	}{
		{
			name:     "nil input returns nil",
			sections: nil,
			want:     nil,
		},
		{
			name:     "empty slice returns nil",
			sections: []string{},
			want:     nil,
		},
		{
			name:     "single valid section",
			sections: []string{"tasks"},
			want:     map[string]bool{"tasks": true},
		},
		{
			name:     "multiple valid sections",
			sections: []string{"tasks", "goals", "rss"},
			want:     map[string]bool{"tasks": true, "goals": true, "rss": true},
		},
		{
			name:     "unknown section silently ignored",
			sections: []string{"tasks", "unknown_section", "goals"},
			want:     map[string]bool{"tasks": true, "goals": true},
		},
		{
			name:     "all unknown sections returns empty map",
			sections: []string{"bad1", "bad2"},
			want:     map[string]bool{},
		},
		{
			name:     "duplicates produce single entry",
			sections: []string{"tasks", "tasks", "goals"},
			want:     map[string]bool{"tasks": true, "goals": true},
		},
		{
			name:     "all valid section names accepted",
			sections: []string{"tasks", "activity", "build_logs", "projects", "goals", "insights", "reflection", "planning_history", "rss", "plan", "completions", "pipeline_health", "rss_highlights", "agent_tasks", "content_pipeline"},
			want: map[string]bool{
				"tasks": true, "activity": true, "build_logs": true,
				"projects": true, "goals": true, "insights": true,
				"reflection": true, "planning_history": true, "rss": true,
				"plan": true, "completions": true, "pipeline_health": true,
				"rss_highlights": true, "agent_tasks": true, "content_pipeline": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildSectionSet(tt.sections)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("buildSectionSet(%v) mismatch (-want +got):\n%s", tt.sections, diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// computeTrend
// ---------------------------------------------------------------------------

func TestComputeTrend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []dailyMetrics
		want    string
	}{
		{
			name:    "empty entries",
			entries: []dailyMetrics{},
			want:    "insufficient_data",
		},
		{
			name:    "single entry",
			entries: []dailyMetrics{{CompletionRate: 0.8}},
			want:    "insufficient_data",
		},
		{
			name: "two entries",
			entries: []dailyMetrics{
				{CompletionRate: 0.9},
				{CompletionRate: 0.5},
			},
			want: "insufficient_data",
		},
		{
			name: "three entries — still insufficient",
			entries: []dailyMetrics{
				{CompletionRate: 0.9},
				{CompletionRate: 0.8},
				{CompletionRate: 0.7},
			},
			want: "insufficient_data",
		},
		{
			name: "four entries — flat trend",
			entries: []dailyMetrics{
				// entries[0:3] = recent (avg 0.8), entries[3:] = older (avg 0.8)
				{CompletionRate: 0.8},
				{CompletionRate: 0.8},
				{CompletionRate: 0.8},
				{CompletionRate: 0.8},
			},
			want: "stable",
		},
		{
			name: "improving trend — recent avg significantly higher",
			entries: []dailyMetrics{
				// recent avg = (0.9+0.9+0.9)/3 = 0.9; older avg = 0.7; diff = +0.2
				{CompletionRate: 0.9},
				{CompletionRate: 0.9},
				{CompletionRate: 0.9},
				{CompletionRate: 0.7},
			},
			want: "up",
		},
		{
			name: "declining trend — recent avg significantly lower",
			entries: []dailyMetrics{
				// recent avg = (0.5+0.5+0.5)/3 = 0.5; older avg = 0.8; diff = -0.3
				{CompletionRate: 0.5},
				{CompletionRate: 0.5},
				{CompletionRate: 0.5},
				{CompletionRate: 0.8},
			},
			want: "down",
		},
		{
			name: "within threshold is stable — diff exactly 0.1",
			entries: []dailyMetrics{
				// recent avg = 0.9, older avg = 0.8, diff = 0.1 → NOT > 0.1 → stable
				{CompletionRate: 0.9},
				{CompletionRate: 0.9},
				{CompletionRate: 0.9},
				{CompletionRate: 0.8},
			},
			want: "stable",
		},
		{
			name: "larger dataset — trend uses only first 3 as recent",
			entries: []dailyMetrics{
				// recent: 0.9, 0.9, 0.9 → avg 0.9
				// older: 0.1, 0.1, 0.1, 0.1 → avg 0.1; diff = +0.8
				{CompletionRate: 0.9},
				{CompletionRate: 0.9},
				{CompletionRate: 0.9},
				{CompletionRate: 0.1},
				{CompletionRate: 0.1},
				{CompletionRate: 0.1},
				{CompletionRate: 0.1},
			},
			want: "up",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := computeTrend(tt.entries)
			if got != tt.want {
				t.Errorf("computeTrend() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// computeSkipCount
// ---------------------------------------------------------------------------

func TestComputeSkipCount(t *testing.T) {
	t.Parallel()

	int32Ptr := func(v int32) *int32 { return &v }

	tests := []struct {
		name          string
		overdueDays   int
		isRecurring   bool
		recurInterval *int32
		want          int
	}{
		{
			name:        "zero overdue days",
			overdueDays: 0,
			want:        0,
		},
		{
			name:        "negative overdue days",
			overdueDays: -1,
			want:        0,
		},
		{
			name:          "recurring daily — 3 days overdue = 3 skips",
			overdueDays:   3,
			isRecurring:   true,
			recurInterval: int32Ptr(1),
			want:          3,
		},
		{
			name:          "recurring weekly — 14 days overdue = 2 skips",
			overdueDays:   14,
			isRecurring:   true,
			recurInterval: int32Ptr(7),
			want:          2,
		},
		{
			name:          "recurring every 3 days — 10 days overdue = 3 skips",
			overdueDays:   10,
			isRecurring:   true,
			recurInterval: int32Ptr(3),
			want:          3,
		},
		{
			name:          "recurring but interval is zero — falls through to non-recurring logic",
			overdueDays:   10,
			isRecurring:   true,
			recurInterval: int32Ptr(0),
			want:          1, // 10/7 = 1
		},
		{
			name:          "recurring but nil interval — falls through",
			overdueDays:   14,
			isRecurring:   true,
			recurInterval: nil,
			want:          2, // 14/7 = 2
		},
		{
			name:        "non-recurring — 6 days overdue — under weekly threshold",
			overdueDays: 6,
			isRecurring: false,
			want:        0,
		},
		{
			name:        "non-recurring — exactly 7 days overdue",
			overdueDays: 7,
			isRecurring: false,
			want:        1,
		},
		{
			name:        "non-recurring — 21 days overdue = 3 skips",
			overdueDays: 21,
			isRecurring: false,
			want:        3,
		},
		{
			name:        "non-recurring — 8 days overdue = 1 skip",
			overdueDays: 8,
			isRecurring: false,
			want:        1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := computeSkipCount(tt.overdueDays, tt.isRecurring, tt.recurInterval)
			if got != tt.want {
				t.Errorf("computeSkipCount(%d, %v, %v) = %d, want %d",
					tt.overdueDays, tt.isRecurring, tt.recurInterval, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isProjectNeglected
// ---------------------------------------------------------------------------

func TestIsProjectNeglected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		daysSinceActivity int
		cadence           string
		want              bool
	}{
		{
			name:              "daily cadence — 1 day is fine",
			daysSinceActivity: 1,
			cadence:           "daily",
			want:              false,
		},
		{
			name:              "daily cadence — at threshold",
			daysSinceActivity: 2,
			cadence:           "daily",
			want:              false,
		},
		{
			name:              "daily cadence — over threshold",
			daysSinceActivity: 3,
			cadence:           "daily",
			want:              true,
		},
		{
			name:              "weekly cadence — 10 days is fine",
			daysSinceActivity: 10,
			cadence:           "weekly",
			want:              false,
		},
		{
			name:              "weekly cadence — 11 days is neglected",
			daysSinceActivity: 11,
			cadence:           "weekly",
			want:              true,
		},
		{
			name:              "biweekly cadence — 21 days is fine",
			daysSinceActivity: 21,
			cadence:           "biweekly",
			want:              false,
		},
		{
			name:              "biweekly cadence — 22 days is neglected",
			daysSinceActivity: 22,
			cadence:           "biweekly",
			want:              true,
		},
		{
			name:              "monthly cadence — 45 days is fine",
			daysSinceActivity: 45,
			cadence:           "monthly",
			want:              false,
		},
		{
			name:              "monthly cadence — 46 days is neglected",
			daysSinceActivity: 46,
			cadence:           "monthly",
			want:              true,
		},
		{
			name:              "on_hold cadence — 9998 days is fine",
			daysSinceActivity: 9998,
			cadence:           "on_hold",
			want:              false,
		},
		{
			name:              "on_hold cadence — 9999 days is fine",
			daysSinceActivity: 9999,
			cadence:           "on_hold",
			want:              false,
		},
		{
			name:              "on_hold cadence — 10000 days is neglected",
			daysSinceActivity: 10000,
			cadence:           "on_hold",
			want:              true,
		},
		{
			name:              "unknown cadence defaults to weekly threshold 10",
			daysSinceActivity: 10,
			cadence:           "unknown",
			want:              false,
		},
		{
			name:              "unknown cadence defaults to weekly threshold — 11 neglected",
			daysSinceActivity: 11,
			cadence:           "unknown",
			want:              true,
		},
		{
			name:              "empty cadence defaults to weekly threshold",
			daysSinceActivity: 11,
			cadence:           "",
			want:              true,
		},
		{
			name:              "zero days since activity is never neglected",
			daysSinceActivity: 0,
			cadence:           "daily",
			want:              false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isProjectNeglected(tt.daysSinceActivity, tt.cadence)
			if got != tt.want {
				t.Errorf("isProjectNeglected(%d, %q) = %v, want %v",
					tt.daysSinceActivity, tt.cadence, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseAdjustments
// ---------------------------------------------------------------------------

func TestParseAdjustments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata json.RawMessage
		want     []string
	}{
		{
			name:     "nil metadata returns nil",
			metadata: nil,
			want:     nil,
		},
		{
			name:     "empty metadata returns nil",
			metadata: json.RawMessage{},
			want:     nil,
		},
		{
			name:     "empty JSON object returns nil",
			metadata: json.RawMessage(`{}`),
			want:     nil,
		},
		{
			name:     "metadata without adjustments field returns nil",
			metadata: json.RawMessage(`{"completion_rate": 0.8}`),
			want:     nil,
		},
		{
			name:     "empty adjustments array returns nil",
			metadata: json.RawMessage(`{"adjustments": []}`),
			want:     nil,
		},
		{
			name:     "single adjustment",
			metadata: json.RawMessage(`{"adjustments": ["moved task to tomorrow"]}`),
			want:     []string{"moved task to tomorrow"},
		},
		{
			name:     "multiple adjustments",
			metadata: json.RawMessage(`{"adjustments": ["reduced scope", "skipped standup", "added urgent fix"]}`),
			want:     []string{"reduced scope", "skipped standup", "added urgent fix"},
		},
		{
			name:     "malformed JSON returns nil",
			metadata: json.RawMessage(`{not valid json`),
			want:     nil,
		},
		{
			name:     "adjustments alongside other fields",
			metadata: json.RawMessage(`{"tasks_planned": 5, "adjustments": ["focused on one thing"], "energy_pattern": "morning"}`),
			want:     []string{"focused on one thing"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseAdjustments(tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("parseAdjustments() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// FuzzParseAdjustments ensures parseAdjustments never panics on arbitrary input.
func FuzzParseAdjustments(f *testing.F) {
	f.Add(`{}`)
	f.Add(`{"adjustments": ["a", "b"]}`)
	f.Add(`{"adjustments": null}`)
	f.Add(`not json at all`)
	f.Add(`{"adjustments": [1, 2, 3]}`)

	f.Fuzz(func(t *testing.T, input string) {
		_ = parseAdjustments(json.RawMessage(input))
	})
}

// ---------------------------------------------------------------------------
// parseInsightBrief
// ---------------------------------------------------------------------------

func TestParseInsightBrief(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		note session.Note
		want insightBrief
	}{
		{
			name: "nil metadata returns bare brief with ID and date",
			note: session.Note{
				ID:        42,
				CreatedAt: baseTime,
				Metadata:  nil,
			},
			want: insightBrief{
				ID:        42,
				CreatedAt: "2026-01-15",
			},
		},
		{
			name: "empty metadata returns bare brief",
			note: session.Note{
				ID:        10,
				CreatedAt: baseTime,
				Metadata:  json.RawMessage{},
			},
			want: insightBrief{
				ID:        10,
				CreatedAt: "2026-01-15",
			},
		},
		{
			name: "full metadata populated",
			note: session.Note{
				ID:        7,
				CreatedAt: baseTime,
				Metadata: json.RawMessage(`{
					"hypothesis": "morning tasks finish faster",
					"status": "unverified",
					"project": "koopa0-dev"
				}`),
			},
			want: insightBrief{
				ID:         7,
				Hypothesis: "morning tasks finish faster",
				Status:     "unverified",
				Project:    "koopa0-dev",
				CreatedAt:  "2026-01-15",
			},
		},
		{
			name: "partial metadata — only hypothesis",
			note: session.Note{
				ID:        3,
				CreatedAt: baseTime,
				Metadata:  json.RawMessage(`{"hypothesis": "pair programming helps"}`),
			},
			want: insightBrief{
				ID:         3,
				Hypothesis: "pair programming helps",
				CreatedAt:  "2026-01-15",
			},
		},
		{
			name: "malformed JSON returns bare brief",
			note: session.Note{
				ID:        5,
				CreatedAt: baseTime,
				Metadata:  json.RawMessage(`{bad json`),
			},
			want: insightBrief{
				ID:        5,
				CreatedAt: "2026-01-15",
			},
		},
		{
			name: "missing project field is empty string",
			note: session.Note{
				ID:        9,
				CreatedAt: baseTime,
				Metadata:  json.RawMessage(`{"hypothesis": "h", "status": "verified"}`),
			},
			want: insightBrief{
				ID:         9,
				Hypothesis: "h",
				Status:     "verified",
				Project:    "",
				CreatedAt:  "2026-01-15",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseInsightBrief(&tt.note)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("parseInsightBrief() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// FuzzParseInsightBrief ensures parseInsightBrief never panics on arbitrary metadata.
func FuzzParseInsightBrief(f *testing.F) {
	f.Add(`{}`)
	f.Add(`{"hypothesis": "test", "status": "unverified", "project": "p"}`)
	f.Add(`{"hypothesis": null}`)
	f.Add(`not json`)

	f.Fuzz(func(t *testing.T, metadata string) {
		n := session.Note{
			ID:        1,
			CreatedAt: time.Now(),
			Metadata:  json.RawMessage(metadata),
		}
		_ = parseInsightBrief(&n)
	})
}

// ---------------------------------------------------------------------------
// parseDailyMetrics
// ---------------------------------------------------------------------------

func TestParseDailyMetrics(t *testing.T) {
	t.Parallel()

	noteDate := time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		note session.Note
		want *dailyMetrics
	}{
		{
			name: "nil metadata returns nil",
			note: session.Note{NoteDate: noteDate, Metadata: nil},
			want: nil,
		},
		{
			name: "empty metadata returns nil",
			note: session.Note{NoteDate: noteDate, Metadata: json.RawMessage{}},
			want: nil,
		},
		{
			name: "malformed JSON returns nil",
			note: session.Note{NoteDate: noteDate, Metadata: json.RawMessage(`{bad json`)},
			want: nil,
		},
		{
			name: "empty JSON object returns zero-value struct",
			note: session.Note{NoteDate: noteDate, Metadata: json.RawMessage(`{}`)},
			want: &dailyMetrics{Date: "2026-03-10"},
		},
		{
			name: "full metrics populated",
			note: session.Note{
				NoteDate: noteDate,
				Metadata: json.RawMessage(`{
					"tasks_planned": 8,
					"tasks_completed": 6,
					"tasks_committed": 5,
					"tasks_pulled": 1,
					"completion_rate": 0.75,
					"committed_completion_rate": 0.80,
					"energy_pattern": "morning_peak"
				}`),
			},
			want: &dailyMetrics{
				Date:                    "2026-03-10",
				TasksPlanned:            8,
				TasksCompleted:          6,
				TasksCommitted:          5,
				TasksPulled:             1,
				CompletionRate:          0.75,
				CommittedCompletionRate: 0.80,
				EnergyPattern:           "morning_peak",
			},
		},
		{
			name: "partial metadata — only completion rate",
			note: session.Note{
				NoteDate: noteDate,
				Metadata: json.RawMessage(`{"completion_rate": 0.5}`),
			},
			want: &dailyMetrics{
				Date:           "2026-03-10",
				CompletionRate: 0.5,
			},
		},
		{
			name: "zero values in metadata — returns zero-value struct not nil",
			note: session.Note{
				NoteDate: noteDate,
				Metadata: json.RawMessage(`{"tasks_planned": 0, "tasks_completed": 0, "completion_rate": 0.0}`),
			},
			want: &dailyMetrics{
				Date: "2026-03-10",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseDailyMetrics(&tt.note)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("parseDailyMetrics() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// FuzzParseDailyMetrics ensures parseDailyMetrics never panics on arbitrary metadata.
func FuzzParseDailyMetrics(f *testing.F) {
	f.Add(`{}`)
	f.Add(`{"tasks_planned": 5, "completion_rate": 0.8}`)
	f.Add(`{"tasks_planned": "not a number"}`)
	f.Add(`not json`)
	f.Add(`null`)

	f.Fuzz(func(t *testing.T, metadata string) {
		n := session.Note{
			NoteDate: time.Now(),
			Metadata: json.RawMessage(metadata),
		}
		_ = parseDailyMetrics(&n)
	})
}

// ---------------------------------------------------------------------------
// buildPlanningHistory
// ---------------------------------------------------------------------------

func TestBuildPlanningHistory(t *testing.T) {
	t.Parallel()

	makeNote := func(dateStr string, planned, completed int, rate float64) session.Note {
		meta, _ := json.Marshal(map[string]any{
			"tasks_planned":   planned,
			"tasks_completed": completed,
			"completion_rate": rate,
		})
		d, _ := time.Parse(time.DateOnly, dateStr)
		return session.Note{NoteDate: d, Metadata: json.RawMessage(meta)}
	}

	t.Run("empty notes returns no_data trend", func(t *testing.T) {
		t.Parallel()
		got := buildPlanningHistory(nil, 7)
		assertHistoryTrend(t, got.Trend, "no_data")
		assertHistoryEntriesLen(t, got.Entries, 0)
		if got.Days != 7 {
			t.Errorf("Days = %d, want 7", got.Days)
		}
		if got.CapacityByDayType == nil {
			t.Error("CapacityByDayType is nil, want empty map")
		}
	})

	t.Run("single entry returns insufficient_data trend", func(t *testing.T) {
		t.Parallel()
		notes := []session.Note{makeNote("2026-03-10", 5, 4, 0.8)}
		got := buildPlanningHistory(notes, 7)
		assertHistoryTrend(t, got.Trend, "insufficient_data")
		assertHistoryEntriesLen(t, got.Entries, 1)
	})

	t.Run("dedup: duplicate dates keep only first", func(t *testing.T) {
		t.Parallel()
		d, _ := time.Parse(time.DateOnly, "2026-03-10")
		meta1, _ := json.Marshal(map[string]any{"tasks_planned": 5, "tasks_completed": 4, "completion_rate": 0.8})
		meta2, _ := json.Marshal(map[string]any{"tasks_planned": 3, "tasks_completed": 2, "completion_rate": 0.6})
		notes := []session.Note{
			{NoteDate: d, Metadata: json.RawMessage(meta1)},
			{NoteDate: d, Metadata: json.RawMessage(meta2)},
		}
		got := buildPlanningHistory(notes, 7)
		assertHistoryEntriesLen(t, got.Entries, 1)
		if got.Entries[0].CompletionRate != 0.8 {
			t.Errorf("CompletionRate = %v, want 0.8 (first entry kept)", got.Entries[0].CompletionRate)
		}
	})

	t.Run("entries capped to recentDays", func(t *testing.T) {
		t.Parallel()
		notes := []session.Note{
			makeNote("2026-03-10", 5, 4, 0.8),
			makeNote("2026-03-09", 6, 5, 0.83),
			makeNote("2026-03-08", 4, 3, 0.75),
			makeNote("2026-03-07", 7, 6, 0.86),
			makeNote("2026-03-06", 5, 4, 0.8),
		}
		got := buildPlanningHistory(notes, 3)
		assertHistoryEntriesLen(t, got.Entries, 3)
	})

	t.Run("averages computed correctly", func(t *testing.T) {
		t.Parallel()
		notes := []session.Note{
			makeNote("2026-03-10", 5, 4, 1.0),
			makeNote("2026-03-09", 5, 3, 0.0),
			makeNote("2026-03-08", 5, 5, 0.5),
			makeNote("2026-03-07", 5, 1, 0.5),
		}
		got := buildPlanningHistory(notes, 7)
		wantAvgRate := (1.0 + 0.0 + 0.5 + 0.5) / 4.0
		if got.AvgCompletionRate != wantAvgRate {
			t.Errorf("AvgCompletionRate = %v, want %v", got.AvgCompletionRate, wantAvgRate)
		}
		wantCap := (4.0 + 3.0 + 5.0 + 1.0) / 4.0
		if got.AvgDailyCapacity != wantCap {
			t.Errorf("AvgDailyCapacity = %v, want %v", got.AvgDailyCapacity, wantCap)
		}
	})

	t.Run("monthly summary only when more data than recent window", func(t *testing.T) {
		t.Parallel()
		notes := []session.Note{
			makeNote("2026-03-10", 5, 4, 0.8),
			makeNote("2026-03-09", 5, 4, 0.8),
			makeNote("2026-03-08", 5, 4, 0.8),
			makeNote("2026-03-07", 5, 4, 0.8),
			makeNote("2026-03-06", 5, 4, 0.8),
		}
		got := buildPlanningHistory(notes, 7)
		if got.MonthlySummary != nil {
			t.Error("MonthlySummary should be nil when entries <= recentDays")
		}
	})

	t.Run("monthly summary present when more data than window", func(t *testing.T) {
		t.Parallel()
		notes := make([]session.Note, 10)
		for i := range 10 {
			dateStr := time.Date(2026, 3, 10-i, 0, 0, 0, 0, time.UTC).Format(time.DateOnly)
			notes[i] = makeNote(dateStr, 5, 4, 0.8)
		}
		got := buildPlanningHistory(notes, 7)
		if got.MonthlySummary == nil {
			t.Fatal("MonthlySummary should not be nil when entries > recentDays")
		}
		if got.MonthlySummary.TotalDaysTracked != 10 {
			t.Errorf("TotalDaysTracked = %d, want 10", got.MonthlySummary.TotalDaysTracked)
		}
	})

	t.Run("notes with nil metadata are skipped", func(t *testing.T) {
		t.Parallel()
		d, _ := time.Parse(time.DateOnly, "2026-03-10")
		notes := []session.Note{
			{NoteDate: d, Metadata: nil},
			makeNote("2026-03-09", 5, 4, 0.8),
		}
		got := buildPlanningHistory(notes, 7)
		assertHistoryEntriesLen(t, got.Entries, 1)
	})
}

func assertHistoryTrend(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("Trend = %q, want %q", got, want)
	}
}

func assertHistoryEntriesLen(t *testing.T, entries []dailyMetrics, want int) {
	t.Helper()
	if len(entries) != want {
		t.Errorf("Entries len = %d, want %d", len(entries), want)
	}
}

// BenchmarkBuildPlanningHistory measures aggregation performance at different data sizes.
func BenchmarkBuildPlanningHistory(b *testing.B) {
	makeNote := func(i int, rate float64) session.Note {
		dateStr := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -i).Format(time.DateOnly)
		meta, _ := json.Marshal(map[string]any{
			"tasks_planned":   5,
			"tasks_completed": 4,
			"completion_rate": rate,
		})
		d, _ := time.Parse(time.DateOnly, dateStr)
		return session.Note{NoteDate: d, Metadata: json.RawMessage(meta)}
	}

	sizes := []struct {
		name string
		n    int
	}{
		{"7days", 7},
		{"30days", 30},
		{"90days", 90},
	}

	for _, s := range sizes {
		notes := make([]session.Note, s.n)
		for i := range s.n {
			notes[i] = makeNote(i, 0.7+float64(i%3)*0.1)
		}
		b.Run(s.name, func(b *testing.B) {
			for b.Loop() {
				buildPlanningHistory(notes, 7)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// computeCapacityMetrics
// ---------------------------------------------------------------------------

func TestComputeCapacityMetrics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		entries         []dailyMetrics
		wantVariance    float64
		wantDayKeys     []string // keys that must exist in byDay map
		wantNoDayKeys   []string // keys that must NOT exist
		approxTolerance float64
	}{
		{
			name:         "empty entries returns zero variance and empty map",
			entries:      nil,
			wantVariance: 0,
		},
		{
			name: "single entry — zero variance",
			entries: []dailyMetrics{
				{Date: "2026-03-10", TasksCompleted: 5}, // tuesday
			},
			wantVariance: 0,
			wantDayKeys:  []string{"tuesday", "weekday_avg"},
		},
		{
			name: "unparseable date is skipped but still contributes to variance",
			entries: []dailyMetrics{
				{Date: "not-a-date", TasksCompleted: 4},
				{Date: "2026-03-09", TasksCompleted: 4}, // monday
			},
			wantVariance: 0,
		},
		{
			name: "weekend days get weekend_avg",
			entries: []dailyMetrics{
				{Date: "2026-03-14", TasksCompleted: 2}, // saturday
				{Date: "2026-03-15", TasksCompleted: 4}, // sunday
			},
			wantDayKeys:   []string{"saturday", "sunday", "weekend_avg"},
			wantNoDayKeys: []string{"weekday_avg"},
		},
		{
			name: "mixed weekday and weekend",
			entries: []dailyMetrics{
				{Date: "2026-03-09", TasksCompleted: 6}, // monday
				{Date: "2026-03-10", TasksCompleted: 4}, // tuesday
				{Date: "2026-03-14", TasksCompleted: 2}, // saturday
			},
			wantDayKeys: []string{"monday", "tuesday", "saturday", "weekday_avg", "weekend_avg"},
		},
		{
			name: "two identical capacities — zero variance",
			entries: []dailyMetrics{
				{Date: "2026-03-09", TasksCompleted: 4}, // monday
				{Date: "2026-03-16", TasksCompleted: 4}, // monday
			},
			wantVariance:    0,
			approxTolerance: 1e-9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotByDay, gotVariance := computeCapacityMetrics(tt.entries)
			assertCapacityVariance(t, gotVariance, tt.wantVariance, tt.approxTolerance)
			assertMapKeys(t, gotByDay, tt.wantDayKeys, tt.wantNoDayKeys)
		})
	}
}

func assertCapacityVariance(t *testing.T, got, want, tolerance float64) {
	t.Helper()
	if tolerance > 0 {
		if diff := want - got; diff < -tolerance || diff > tolerance {
			t.Errorf("variance = %v, want %v (±%v)", got, want, tolerance)
		}
	} else if want != 0 && got == 0 {
		t.Errorf("variance = 0, want non-zero")
	}
}

func assertMapKeys(t *testing.T, m map[string]float64, wantKeys, noKeys []string) {
	t.Helper()
	for _, key := range wantKeys {
		if _, ok := m[key]; !ok {
			t.Errorf("byDay missing key %q", key)
		}
	}
	for _, key := range noKeys {
		if _, ok := m[key]; ok {
			t.Errorf("byDay should not have key %q", key)
		}
	}
}

// ---------------------------------------------------------------------------
// computeMonthlySummary
// ---------------------------------------------------------------------------

func TestComputeMonthlySummary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		entries       []dailyMetrics
		capacityByDay map[string]float64
		want          *monthlySummary
	}{
		{
			name: "single entry",
			entries: []dailyMetrics{
				{Date: "2026-03-10", TasksCompleted: 4, CompletionRate: 0.8},
			},
			capacityByDay: map[string]float64{"tuesday": 4.0},
			want: &monthlySummary{
				TotalDaysTracked:  1,
				AvgCompletionRate: 0.8,
				AvgDailyCapacity:  4.0,
				BestDayType:       "tuesday",
				WorstDayType:      "tuesday",
			},
		},
		{
			name: "multiple entries averages correctly",
			entries: []dailyMetrics{
				{Date: "2026-03-09", TasksCompleted: 6, CompletionRate: 1.0},
				{Date: "2026-03-10", TasksCompleted: 2, CompletionRate: 0.5},
			},
			capacityByDay: map[string]float64{
				"monday":  6.0,
				"tuesday": 2.0,
			},
			want: &monthlySummary{
				TotalDaysTracked:  2,
				AvgCompletionRate: 0.75,
				AvgDailyCapacity:  4.0,
				BestDayType:       "monday",
				WorstDayType:      "tuesday",
			},
		},
		{
			name: "aggregated keys weekday_avg and weekend_avg excluded from best/worst",
			entries: []dailyMetrics{
				{Date: "2026-03-09", TasksCompleted: 5, CompletionRate: 0.8},
			},
			capacityByDay: map[string]float64{
				"monday":      5.0,
				"weekday_avg": 5.0,
				"weekend_avg": 2.0,
			},
			want: &monthlySummary{
				TotalDaysTracked:  1,
				AvgCompletionRate: 0.8,
				AvgDailyCapacity:  5.0,
				BestDayType:       "monday",
				WorstDayType:      "monday",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := computeMonthlySummary(tt.entries, tt.capacityByDay)
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateApprox(0.0001, 0)); diff != "" {
				t.Errorf("computeMonthlySummary() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ensureMorningDefaults
// ---------------------------------------------------------------------------

func TestEnsureMorningDefaults(t *testing.T) {
	t.Parallel()

	t.Run("fully nil output gets all defaults", func(t *testing.T) {
		t.Parallel()
		out := &MorningContextOutput{}
		ensureMorningDefaults(out)

		assertMorningSlicesNotNil(t, out)
		assertMorningMapsNotNil(t, out)
		assertMorningPlanningHistoryDefaults(t, out)
	})

	t.Run("existing slices are not overwritten", func(t *testing.T) {
		t.Parallel()
		existing := []morningTask{{ID: "existing"}}
		out := &MorningContextOutput{
			OverdueTasks: existing,
		}
		ensureMorningDefaults(out)
		if len(out.OverdueTasks) != 1 || out.OverdueTasks[0].ID != "existing" {
			t.Error("ensureMorningDefaults overwrote existing OverdueTasks")
		}
	})

	t.Run("existing planning history is preserved", func(t *testing.T) {
		t.Parallel()
		ph := &planningHistorySummary{
			Trend: "up",
			Days:  7,
		}
		out := &MorningContextOutput{PlanningHistory: ph}
		ensureMorningDefaults(out)
		if out.PlanningHistory.Trend != "up" {
			t.Errorf("PlanningHistory.Trend = %q, want %q", out.PlanningHistory.Trend, "up")
		}
		// Entries within existing planning history still gets defaulted
		if out.PlanningHistory.Entries == nil {
			t.Error("PlanningHistory.Entries should have been defaulted to empty slice")
		}
	})

	t.Run("all slices are empty not nil after defaults", func(t *testing.T) {
		t.Parallel()
		out := &MorningContextOutput{}
		ensureMorningDefaults(out)

		// JSON serialization test: nil slices serialize to null, empty to []
		data, err := json.Marshal(out)
		if err != nil {
			t.Fatalf("marshaling output: %v", err)
		}
		jsonStr := string(data)
		// None of these should appear as null in JSON
		nullFields := []string{
			`"overdue_tasks":null`,
			`"today_tasks":null`,
			`"upcoming_tasks":null`,
			`"my_day_tasks":null`,
			`"recent_build_logs":null`,
			`"projects":null`,
			`"goals":null`,
			`"active_insights":null`,
			`"pending_recommendations":null`,
			`"today_completions":null`,
			`"urgent_rss":null`,
		}
		for _, nullField := range nullFields {
			if strings.Contains(jsonStr, nullField) {
				t.Errorf("JSON output contains %q (should be [] not null)", nullField)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// isCompletionEvent
// ---------------------------------------------------------------------------

func TestIsCompletionEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		eventType string
		source    string
		metadata  json.RawMessage
		want      bool
	}{
		{
			name:      "task_completed from mcp is always completion",
			eventType: "task_completed",
			source:    "mcp",
			metadata:  nil,
			want:      true,
		},
		{
			name:      "task_completed from notion is also completion",
			eventType: "task_completed",
			source:    "notion",
			metadata:  nil,
			want:      true,
		},
		{
			name:      "task_status_change from notion with Done status",
			eventType: "task_status_change",
			source:    "notion",
			metadata:  json.RawMessage(`{"status": "Done"}`),
			want:      true,
		},
		{
			name:      "task_status_change from notion with non-Done status",
			eventType: "task_status_change",
			source:    "notion",
			metadata:  json.RawMessage(`{"status": "In Progress"}`),
			want:      false,
		},
		{
			name:      "task_status_change from mcp — not a notion completion",
			eventType: "task_status_change",
			source:    "mcp",
			metadata:  json.RawMessage(`{"status": "Done"}`),
			want:      false,
		},
		{
			name:      "task_status_change from notion with malformed JSON",
			eventType: "task_status_change",
			source:    "notion",
			metadata:  json.RawMessage(`{bad json`),
			want:      false,
		},
		{
			name:      "task_status_change from notion with nil metadata",
			eventType: "task_status_change",
			source:    "notion",
			metadata:  nil,
			want:      false,
		},
		{
			name:      "unrelated event type",
			eventType: "project_update",
			source:    "notion",
			metadata:  json.RawMessage(`{"status": "Done"}`),
			want:      false,
		},
		{
			name:      "empty event type",
			eventType: "",
			source:    "notion",
			metadata:  json.RawMessage(`{"status": "Done"}`),
			want:      false,
		},
		{
			name:      "task_status_change from notion — status key missing",
			eventType: "task_status_change",
			source:    "notion",
			metadata:  json.RawMessage(`{"other_field": "value"}`),
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isCompletionEvent(tt.eventType, tt.source, tt.metadata)
			if got != tt.want {
				t.Errorf("isCompletionEvent(%q, %q, %q) = %v, want %v",
					tt.eventType, tt.source, tt.metadata, got, tt.want)
			}
		})
	}
}

// assertMorningSlicesNotNil checks that all slice fields in MorningContextOutput are non-nil.
func assertMorningSlicesNotNil(t *testing.T, out *MorningContextOutput) {
	t.Helper()
	checks := []struct {
		name string
		val  any
	}{
		{"OverdueTasks", out.OverdueTasks},
		{"TodayTasks", out.TodayTasks},
		{"UpcomingTasks", out.UpcomingTasks},
		{"MyDayTasks", out.MyDayTasks},
		{"RecentBuildLogs", out.RecentBuildLogs},
		{"Projects", out.Projects},
		{"Goals", out.Goals},
		{"ActiveInsights", out.ActiveInsights},
		{"PendingRecommendations", out.PendingRecommendations},
		{"TodayCompletions", out.TodayCompletions},
		{"UrgentRSS", out.UrgentRSS},
	}
	for _, c := range checks {
		if c.val == nil {
			t.Errorf("%s is nil after ensureMorningDefaults", c.name)
		}
	}
}

// assertMorningPlanningHistoryDefaults checks that PlanningHistory is properly initialized.
func assertMorningPlanningHistoryDefaults(t *testing.T, out *MorningContextOutput) {
	t.Helper()
	if out.PlanningHistory == nil {
		t.Fatal("PlanningHistory is nil")
	}
	if out.PlanningHistory.Entries == nil {
		t.Error("PlanningHistory.Entries is nil")
	}
	if out.PlanningHistory.CapacityByDayType == nil {
		t.Error("PlanningHistory.CapacityByDayType is nil")
	}
	if out.PlanningHistory.Trend != "no_data" {
		t.Errorf("PlanningHistory.Trend = %q, want %q", out.PlanningHistory.Trend, "no_data")
	}
}

// assertMorningMapsNotNil checks that map fields inside MorningContextOutput are non-nil.
func assertMorningMapsNotNil(t *testing.T, out *MorningContextOutput) {
	t.Helper()
	if out.RecentActivity.BySource == nil {
		t.Error("RecentActivity.BySource is nil")
	}
	if out.RecentActivity.ByProject == nil {
		t.Error("RecentActivity.ByProject is nil")
	}
	if out.RecentActivity.TopEvents == nil {
		t.Error("RecentActivity.TopEvents is nil")
	}
}

// FuzzIsCompletionEvent ensures isCompletionEvent never panics on arbitrary metadata.
func FuzzIsCompletionEvent(f *testing.F) {
	f.Add("task_completed", "mcp", `{}`)
	f.Add("task_status_change", "notion", `{"status": "Done"}`)
	f.Add("task_status_change", "notion", `not json`)
	f.Add("", "", `null`)

	f.Fuzz(func(t *testing.T, eventType, source, metadata string) {
		_ = isCompletionEvent(eventType, source, json.RawMessage(metadata))
	})
}
