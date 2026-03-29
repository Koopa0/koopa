package learning

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/content"
)

func entry(tags []string, daysAgo int) content.TagEntry {
	return content.TagEntry{
		ID:        uuid.New(),
		Tags:      tags,
		CreatedAt: time.Now().AddDate(0, 0, -daysAgo),
	}
}

func TestCoverageMatrix(t *testing.T) {
	entries := []content.TagEntry{
		entry([]string{"dp", "ac-independent"}, 1),
		entry([]string{"dp", "greedy", "ac-with-hints"}, 2),
		entry([]string{"dp", "ac-after-solution"}, 3),
		entry([]string{"two-pointers", "ac-independent"}, 1),
		entry([]string{"weakness:edge-cases"}, 5), // not a topic tag, should be ignored
	}

	result := CoverageMatrix(entries, 30)

	if result.TotalEntries != 5 {
		t.Errorf("TotalEntries = %d, want 5", result.TotalEntries)
	}
	if result.PeriodDays != 30 {
		t.Errorf("PeriodDays = %d, want 30", result.PeriodDays)
	}
	// dp should have 3 entries, two-pointers 1, greedy 1
	if len(result.Topics) != 3 {
		t.Fatalf("Topics count = %d, want 3", len(result.Topics))
	}
	// sorted by count desc, dp first
	if result.Topics[0].Topic != "dp" || result.Topics[0].Count != 3 {
		t.Errorf("first topic = %s (count %d), want dp (count 3)", result.Topics[0].Topic, result.Topics[0].Count)
	}
	// dp should have result breakdown
	if diff := cmp.Diff(map[string]int{"ac-independent": 1, "ac-with-hints": 1, "ac-after-solution": 1}, result.Topics[0].Results); diff != "" {
		t.Errorf("dp results mismatch (-want +got):\n%s", diff)
	}
}

func TestCoverageMatrix_Empty(t *testing.T) {
	result := CoverageMatrix(nil, 365)
	if len(result.Topics) != 0 {
		t.Errorf("Topics = %v, want empty", result.Topics)
	}
	if result.TotalEntries != 0 {
		t.Errorf("TotalEntries = %d, want 0", result.TotalEntries)
	}
}

func TestTagSummary(t *testing.T) {
	entries := []content.TagEntry{
		entry([]string{"dp", "ac-independent", "weakness:edge-cases"}, 1),
		entry([]string{"dp", "two-pointers", "weakness:edge-cases"}, 2),
		entry([]string{"greedy", "ac-with-hints"}, 3),
	}

	tests := []struct {
		name      string
		prefix    string
		wantCount int
		wantFirst string
	}{
		{"no prefix", "", 6, "dp"},                                 // dp:2, weakness:edge-cases:2, then 4 others
		{"weakness prefix", "weakness:", 1, "weakness:edge-cases"}, // only weakness tags
		{"ac prefix", "ac-", 2, "ac-independent"},                  // ac-independent:1, ac-with-hints:1
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TagSummary(entries, tt.prefix, 90)
			if result.TotalTags != tt.wantCount {
				t.Errorf("TotalTags = %d, want %d", result.TotalTags, tt.wantCount)
			}
			if len(result.Tags) > 0 && result.Tags[0].Tag != tt.wantFirst {
				t.Errorf("first tag = %s, want %s", result.Tags[0].Tag, tt.wantFirst)
			}
		})
	}
}

func TestWeaknessTrend(t *testing.T) {
	tests := []struct {
		name      string
		entries   []content.TagEntry
		tag       string
		wantTrend string
		wantCount int
	}{
		{
			name:      "insufficient data",
			entries:   []content.TagEntry{entry([]string{"weakness:x", "ac-independent"}, 1)},
			tag:       "weakness:x",
			wantTrend: "insufficient-data",
			wantCount: 1,
		},
		{
			name: "improving",
			entries: []content.TagEntry{
				entry([]string{"weakness:x", "ac-after-solution"}, 5),
				entry([]string{"weakness:x", "ac-with-hints"}, 4),
				entry([]string{"weakness:x", "ac-independent"}, 3),
				entry([]string{"weakness:x", "ac-independent"}, 2),
				entry([]string{"weakness:x", "ac-independent"}, 1),
			},
			tag:       "weakness:x",
			wantTrend: "improving",
			wantCount: 5,
		},
		{
			name: "declining",
			entries: []content.TagEntry{
				entry([]string{"weakness:x", "ac-independent"}, 5),
				entry([]string{"weakness:x", "ac-after-solution"}, 4),
				entry([]string{"weakness:x", "ac-after-solution"}, 3),
				entry([]string{"weakness:x", "incomplete"}, 2),
				entry([]string{"weakness:x", "incomplete"}, 1),
			},
			tag:       "weakness:x",
			wantTrend: "declining",
			wantCount: 5,
		},
		{
			name: "filters unrelated entries",
			entries: []content.TagEntry{
				entry([]string{"weakness:x", "ac-independent"}, 3),
				entry([]string{"weakness:y", "ac-after-solution"}, 2), // different tag
				entry([]string{"weakness:x", "ac-independent"}, 1),
				entry([]string{"dp", "ac-independent"}, 1), // no weakness tag
			},
			tag:       "weakness:x",
			wantTrend: "insufficient-data", // only 2 matches
			wantCount: 2,
		},
		{
			name:      "no matches",
			entries:   []content.TagEntry{entry([]string{"dp", "ac-independent"}, 1)},
			tag:       "weakness:nonexistent",
			wantTrend: "insufficient-data",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WeaknessTrend(tt.entries, tt.tag, 30)
			if result.Trend != tt.wantTrend {
				t.Errorf("Trend = %q, want %q", result.Trend, tt.wantTrend)
			}
			if len(result.Occurrences) != tt.wantCount {
				t.Errorf("Occurrences count = %d, want %d", len(result.Occurrences), tt.wantCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CoverageMatrix — adversarial / boundary
// ---------------------------------------------------------------------------

func TestCoverageMatrix_NoTopicTags(t *testing.T) {
	t.Parallel()

	// All entries carry only result and weakness tags — no topic tags.
	entries := []content.TagEntry{
		entry([]string{"ac-independent", "weakness:edge-cases"}, 1),
		entry([]string{"incomplete", "weakness:implementation"}, 2),
	}
	result := CoverageMatrix(entries, 90)
	if len(result.Topics) != 0 {
		t.Errorf("CoverageMatrix() Topics = %v, want empty (no topic tags in input)", result.Topics)
	}
	if result.TotalEntries != 2 {
		t.Errorf("CoverageMatrix() TotalEntries = %d, want 2", result.TotalEntries)
	}
}

func TestCoverageMatrix_MultipleTopicsPerEntry(t *testing.T) {
	t.Parallel()

	// A single entry with both "dp" and "graph" should count once for each.
	entries := []content.TagEntry{
		entry([]string{"dp", "graph", "ac-independent"}, 0),
	}
	result := CoverageMatrix(entries, 30)
	if len(result.Topics) != 2 {
		t.Fatalf("CoverageMatrix() Topics len = %d, want 2", len(result.Topics))
	}
	// dp and graph each have count 1
	for _, tc := range result.Topics {
		if tc.Count != 1 {
			t.Errorf("CoverageMatrix() topic %q count = %d, want 1", tc.Topic, tc.Count)
		}
	}
}

func TestCoverageMatrix_SortStability(t *testing.T) {
	t.Parallel()

	// dp:3, graph:3, two-pointers:1 — topics with equal count must be in a
	// deterministic order (sorted descending by count; ties are allowed any order
	// but the slice must be stable between calls).
	entries := []content.TagEntry{
		entry([]string{"dp", "ac-independent"}, 3),
		entry([]string{"dp", "ac-independent"}, 2),
		entry([]string{"dp", "ac-independent"}, 1),
		entry([]string{"graph", "ac-independent"}, 3),
		entry([]string{"graph", "ac-independent"}, 2),
		entry([]string{"graph", "ac-independent"}, 1),
		entry([]string{"two-pointers", "ac-independent"}, 1),
	}

	r1 := CoverageMatrix(entries, 90)
	r2 := CoverageMatrix(entries, 90)

	if diff := cmp.Diff(r1, r2); diff != "" {
		t.Errorf("CoverageMatrix() not deterministic between calls (-first +second):\n%s", diff)
	}
	// two-pointers must be last (count=1 < 3)
	last := r1.Topics[len(r1.Topics)-1]
	if last.Topic != "two-pointers" {
		t.Errorf("CoverageMatrix() last topic = %q, want %q", last.Topic, "two-pointers")
	}
}

func TestCoverageMatrix_EntryWithNoResult(t *testing.T) {
	t.Parallel()

	// An entry with a topic but no result tag must still be counted.
	entries := []content.TagEntry{
		entry([]string{"dp"}, 1), // no result tag
	}
	result := CoverageMatrix(entries, 30)
	if len(result.Topics) != 1 {
		t.Fatalf("CoverageMatrix() Topics len = %d, want 1", len(result.Topics))
	}
	if result.Topics[0].Count != 1 {
		t.Errorf("CoverageMatrix() dp count = %d, want 1", result.Topics[0].Count)
	}
	// results map should be empty (no result tags to accumulate)
	if len(result.Topics[0].Results) != 0 {
		t.Errorf("CoverageMatrix() dp.Results = %v, want empty", result.Topics[0].Results)
	}
}

// ---------------------------------------------------------------------------
// TagSummary — adversarial / boundary
// ---------------------------------------------------------------------------

func TestTagSummary_Empty(t *testing.T) {
	t.Parallel()

	result := TagSummary(nil, "", 90)
	if len(result.Tags) != 0 {
		t.Errorf("TagSummary(nil) Tags = %v, want empty", result.Tags)
	}
	if result.TotalTags != 0 {
		t.Errorf("TagSummary(nil) TotalTags = %d, want 0", result.TotalTags)
	}
}

func TestTagSummary_TieSortedAlphabetically(t *testing.T) {
	t.Parallel()

	// "alpha" and "beta" both appear once — alphabetical tiebreak expected.
	entries := []content.TagEntry{
		entry([]string{"beta"}, 1),
		entry([]string{"alpha"}, 2),
	}
	result := TagSummary(entries, "", 90)
	if len(result.Tags) < 2 {
		t.Fatalf("TagSummary() Tags len = %d, want >= 2", len(result.Tags))
	}
	if result.Tags[0].Tag != "alpha" {
		t.Errorf("TagSummary() first tag (tie, alphabetical) = %q, want %q", result.Tags[0].Tag, "alpha")
	}
}

func TestTagSummary_PrefixNoMatch(t *testing.T) {
	t.Parallel()

	entries := []content.TagEntry{
		entry([]string{"dp", "graph"}, 1),
	}
	result := TagSummary(entries, "weakness:", 90)
	if result.TotalTags != 0 {
		t.Errorf("TagSummary() with non-matching prefix TotalTags = %d, want 0", result.TotalTags)
	}
}

func TestTagSummary_UnicodeTag(t *testing.T) {
	t.Parallel()

	// Tags containing Unicode characters must not panic and must round-trip correctly.
	tag := "weakness:边界条件"
	entries := []content.TagEntry{
		entry([]string{tag}, 1),
	}
	result := TagSummary(entries, "", 90)
	if result.TotalTags != 1 {
		t.Errorf("TagSummary() unicode tag TotalTags = %d, want 1", result.TotalTags)
	}
	if result.Tags[0].Tag != tag {
		t.Errorf("TagSummary() unicode tag = %q, want %q", result.Tags[0].Tag, tag)
	}
}

// ---------------------------------------------------------------------------
// computeTrend — direct tests (pure logic, Q0)
// ---------------------------------------------------------------------------

func TestComputeTrend(t *testing.T) {
	t.Parallel()

	makePoints := func(results ...string) []WeaknessPoint {
		pts := make([]WeaknessPoint, len(results))
		for i, r := range results {
			pts[i] = WeaknessPoint{Date: "2026-01-01", Result: r}
		}
		return pts
	}

	tests := []struct {
		name   string
		points []WeaknessPoint
		want   string
	}{
		{
			name:   "empty",
			points: nil,
			want:   "insufficient-data",
		},
		{
			name:   "one point",
			points: makePoints("ac-independent"),
			want:   "insufficient-data",
		},
		{
			name:   "two points",
			points: makePoints("ac-independent", "ac-independent"),
			want:   "insufficient-data",
		},
		{
			name:   "three identical good results",
			points: makePoints("ac-independent", "ac-independent", "ac-independent"),
			want:   "improving",
		},
		{
			name:   "three bad results",
			points: makePoints("incomplete", "incomplete", "incomplete"),
			want:   "declining",
		},
		{
			name:   "mixed — stable (2 good 2 bad 1 neutral)",
			points: makePoints("ac-independent", "incomplete", "ac-with-hints", "ac-independent", "incomplete"),
			want:   "stable",
		},
		{
			name: "window takes last 5 of 7 — last 5 all good",
			points: makePoints(
				"incomplete", "incomplete",
				"ac-independent", "ac-independent", "ac-independent", "ac-independent", "ac-independent",
			),
			want: "improving",
		},
		{
			name: "window takes last 5 of 7 — last 5 all bad",
			points: makePoints(
				"ac-independent", "ac-independent",
				"incomplete", "incomplete", "incomplete", "incomplete", "incomplete",
			),
			want: "declining",
		},
		{
			name:   "ac-with-hints alone is neutral (not good, not bad)",
			points: makePoints("ac-with-hints", "ac-with-hints", "ac-with-hints"),
			want:   "stable",
		},
		{
			name:   "good == bad + 1 (boundary: not improving)",
			points: makePoints("ac-independent", "ac-independent", "incomplete"),
			want:   "stable",
		},
		{
			name:   "good == bad + 2 (boundary: improving)",
			points: makePoints("ac-independent", "ac-independent", "ac-independent", "incomplete"),
			want:   "improving",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := computeTrend(tt.points)
			if got != tt.want {
				t.Errorf("computeTrend(%v) = %q, want %q", tt.points, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// WeaknessTrend — chronological ordering
// ---------------------------------------------------------------------------

func TestWeaknessTrend_ChronologicalOrder(t *testing.T) {
	t.Parallel()

	// Entries arrive DESC from DB (most recent first).
	// WeaknessTrend must reverse them to chronological order.
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	entries := []content.TagEntry{
		{ID: uuid.New(), Tags: []string{"weakness:x", "ac-independent"}, CreatedAt: base.Add(2 * 24 * time.Hour)}, // newest
		{ID: uuid.New(), Tags: []string{"weakness:x", "ac-after-solution"}, CreatedAt: base.Add(1 * 24 * time.Hour)},
		{ID: uuid.New(), Tags: []string{"weakness:x", "incomplete"}, CreatedAt: base}, // oldest
	}

	result := WeaknessTrend(entries, "weakness:x", 30)

	if len(result.Occurrences) != 3 {
		t.Fatalf("WeaknessTrend() Occurrences len = %d, want 3", len(result.Occurrences))
	}
	// After reversal: oldest first → result should be incomplete, ac-after-solution, ac-independent
	want := []WeaknessPoint{
		{Date: base.Format(time.DateOnly), Result: "incomplete"},
		{Date: base.Add(1 * 24 * time.Hour).Format(time.DateOnly), Result: "ac-after-solution"},
		{Date: base.Add(2 * 24 * time.Hour).Format(time.DateOnly), Result: "ac-independent"},
	}
	if diff := cmp.Diff(want, result.Occurrences, cmpopts.IgnoreFields(WeaknessPoint{}, "Title")); diff != "" {
		t.Errorf("WeaknessTrend() chronological order mismatch (-want +got):\n%s", diff)
	}
}

func TestWeaknessTrend_TagAndPeriodPassThrough(t *testing.T) {
	t.Parallel()

	result := WeaknessTrend(nil, "weakness:focus", 45)
	if result.Tag != "weakness:focus" {
		t.Errorf("WeaknessTrend() Tag = %q, want %q", result.Tag, "weakness:focus")
	}
	if result.PeriodDays != 45 {
		t.Errorf("WeaknessTrend() PeriodDays = %d, want 45", result.PeriodDays)
	}
}
