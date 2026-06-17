// Copyright 2026 Koopa. All rights reserved.

package learning

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestSelectNextTarget pins the session-independent "Next up" picker: it must
// take the HEAD of a severity-ordered weakness slice (never re-sort), render
// a one-line reason, derive the right mastery stage and recency, and
// represent "nothing to recommend" as Empty=true rather than a zero-value
// struct that the card can't tell apart from a real recommendation.
//
// Reason is asserted on the WHOLE rendered string via substring markers so a
// prose tweak doesn't churn the test, but the load-bearing facts (severity
// word, occurrence count, recency phrase) are each pinned.
func TestSelectNextTarget(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

	// daysAgo returns a timestamp n*24h before now.
	daysAgo := func(n int) time.Time { return now.AddDate(0, 0, -n) }

	tests := []struct {
		name string
		// bug each case catches if SelectNextTarget regresses
		bug          string
		weaknesses   []WeaknessRow
		want         NextTarget
		reasonHas    []string
		reasonNotHas []string
	}{
		{
			name:       "empty slice → Empty=true with a renderable reason",
			bug:        "empty input returns a zero NextTarget the card mistakes for a real recommendation (no empty state)",
			weaknesses: nil,
			want: NextTarget{
				Empty:  true,
				Reason: "no concepts need practice in the last 30 days — nothing to recommend yet",
			},
		},
		{
			name: "takes the head — does NOT pick a later, higher-count row",
			bug:  "picker re-sorts or scans for max occurrence_count, overriding the SQL's critical-first ordering and recommending a non-critical concept",
			weaknesses: []WeaknessRow{
				// Head: one critical, low occurrence — must win.
				{ConceptSlug: "two-pointer", ConceptName: "Two Pointer", Domain: "leetcode", OccurrenceCount: 2, CriticalCount: 1, LastSeenAt: daysAgo(3)},
				// Tail: zero critical but huge occurrence — must NOT win.
				{ConceptSlug: "hash-map", ConceptName: "Hash Map", Domain: "leetcode", OccurrenceCount: 99, MinorCount: 99, LastSeenAt: daysAgo(1)},
			},
			want: NextTarget{
				ConceptSlug:       "two-pointer",
				ConceptName:       "Two Pointer",
				Domain:            "leetcode",
				MasteryStage:      StageDeveloping, // 2 observations < floor of 3
				Severity:          "critical",
				DaysSincePractice: 3,
			},
			reasonHas:    []string{"Two Pointer", "critical weakness", "surfaced 2 times", "3 days ago"},
			reasonNotHas: []string{"Hash Map"},
		},
		{
			name: "dominant severity is critical > moderate > minor, first non-zero wins",
			bug:  "severity label uses the largest count instead of the most-urgent band, so a concept with 1 critical + 5 minor reports 'minor'",
			weaknesses: []WeaknessRow{
				{ConceptSlug: "dp", ConceptName: "Dynamic Programming", Domain: "leetcode", OccurrenceCount: 6, CriticalCount: 1, MinorCount: 5, LastSeenAt: daysAgo(0)},
			},
			want: NextTarget{
				ConceptSlug:       "dp",
				ConceptName:       "Dynamic Programming",
				Domain:            "leetcode",
				MasteryStage:      StageStruggling, // 6 weakness observations, past floor
				Severity:          "critical",
				DaysSincePractice: 0,
			},
			reasonHas: []string{"critical weakness", "surfaced 6 times", "last practiced today"},
		},
		{
			name: "mastery stage struggling once occurrence count passes the floor",
			bug:  "stage derived from total signal across all types instead of weakness-only, so a recommended (always-weak) concept never reaches struggling",
			weaknesses: []WeaknessRow{
				{ConceptSlug: "graph", ConceptName: "Graphs", Domain: "leetcode", OccurrenceCount: 3, ModerateCount: 3, LastSeenAt: daysAgo(10)},
			},
			want: NextTarget{
				ConceptSlug:       "graph",
				ConceptName:       "Graphs",
				Domain:            "leetcode",
				MasteryStage:      StageStruggling,
				Severity:          "moderate",
				DaysSincePractice: 10,
			},
			reasonHas: []string{"moderate weakness", "surfaced 3 times", "10 days ago"},
		},
		{
			name: "singular phrasing when occurrence count is exactly one",
			bug:  "reason always says 'surfaced N times' producing 'surfaced 1 times', and pluralizes the recency for a single hit",
			weaknesses: []WeaknessRow{
				{ConceptSlug: "trie", ConceptName: "Trie", Domain: "leetcode", OccurrenceCount: 1, ModerateCount: 1, LastSeenAt: daysAgo(1)},
			},
			want: NextTarget{
				ConceptSlug:       "trie",
				ConceptName:       "Trie",
				Domain:            "leetcode",
				MasteryStage:      StageDeveloping,
				Severity:          "moderate",
				DaysSincePractice: 1,
			},
			reasonHas:    []string{"surfaced once", "last practiced yesterday"},
			reasonNotHas: []string{"1 times", "1 days ago"},
		},
		{
			name: "no severity counts set → severity empty, reason says plain 'weakness'",
			bug:  "reason emits a leading space ('a  weakness') or the word 'weakness' is dropped when severity is empty",
			weaknesses: []WeaknessRow{
				{ConceptSlug: "bitmask", ConceptName: "Bitmask", Domain: "leetcode", OccurrenceCount: 4, LastSeenAt: daysAgo(2)},
			},
			want: NextTarget{
				ConceptSlug:       "bitmask",
				ConceptName:       "Bitmask",
				Domain:            "leetcode",
				MasteryStage:      StageStruggling,
				Severity:          "",
				DaysSincePractice: 2,
			},
			reasonHas:    []string{"a weakness surfaced"},
			reasonNotHas: []string{"a  weakness", "critical", "moderate", "minor"},
		},
		{
			name: "future last_seen (clock skew) floors days at zero, never negative",
			bug:  "days_since_practice goes negative when an observation is timestamped ahead of now",
			weaknesses: []WeaknessRow{
				{ConceptSlug: "skew", ConceptName: "Skew", Domain: "leetcode", OccurrenceCount: 2, CriticalCount: 2, LastSeenAt: now.Add(48 * time.Hour)},
			},
			want: NextTarget{
				ConceptSlug:       "skew",
				ConceptName:       "Skew",
				Domain:            "leetcode",
				MasteryStage:      StageDeveloping,
				Severity:          "critical",
				DaysSincePractice: 0,
			},
			reasonHas: []string{"last practiced today"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := SelectNextTarget(tt.weaknesses, now)

			// Compare the structural fields, ignoring Reason — Reason is
			// asserted separately via substring markers so prose edits do
			// not require updating an exact-string want.
			if diff := cmp.Diff(tt.want, got, cmpopts.IgnoreFields(NextTarget{}, "Reason")); diff != "" {
				t.Errorf("SelectNextTarget(...) mismatch (-want +got):\n%s\nbug guarded: %s", diff, tt.bug)
			}

			// Empty-state reason is pinned exactly (it's a fixed sentence).
			if tt.want.Empty {
				if got.Reason != tt.want.Reason {
					t.Errorf("SelectNextTarget(...).Reason = %q, want %q", got.Reason, tt.want.Reason)
				}
				return
			}

			if got.Reason == "" {
				t.Fatalf("SelectNextTarget(...).Reason is empty; want a rendered sentence (bug: %s)", tt.bug)
			}
			for _, marker := range tt.reasonHas {
				if !strings.Contains(got.Reason, marker) {
					t.Errorf("SelectNextTarget(...).Reason = %q, want substring %q (bug: %s)", got.Reason, marker, tt.bug)
				}
			}
			for _, marker := range tt.reasonNotHas {
				if strings.Contains(got.Reason, marker) {
					t.Errorf("SelectNextTarget(...).Reason = %q, must NOT contain %q (bug: %s)", got.Reason, marker, tt.bug)
				}
			}
		})
	}
}
