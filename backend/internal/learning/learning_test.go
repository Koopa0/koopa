package learning

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
