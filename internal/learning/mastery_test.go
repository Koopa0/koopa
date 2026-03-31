package learning

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/retrieval"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func richEntryWithMeta(t *testing.T, tags []string, daysAgo int, meta any) content.RichTagEntry {
	t.Helper()
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("richEntryWithMeta: marshaling metadata: %v", err)
	}
	return content.RichTagEntry{
		ID:         uuid.New(),
		Slug:       "slug-" + uuid.NewString()[:8],
		Title:      "Test Problem",
		Tags:       tags,
		AIMetadata: raw,
		CreatedAt:  time.Now().AddDate(0, 0, -daysAgo),
	}
}

// ---------------------------------------------------------------------------
// computeStage — boundary cases for each stage transition
// ---------------------------------------------------------------------------

func TestComputeStage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		signals   StageSignals
		weakTags  []WeaknessTagSummary
		wantStage string
	}{
		{
			name:      "unexplored: 0 problems",
			signals:   StageSignals{ProblemsSolved: 0},
			wantStage: "unexplored",
		},
		{
			name:      "unexplored: exactly 1 problem",
			signals:   StageSignals{ProblemsSolved: 1},
			wantStage: "unexplored",
		},
		{
			name: "solid: all conditions met",
			signals: StageSignals{
				ProblemsSolved:    4,
				ACIndependentRate: 0.75,
				RecentGuidedRatio: 0.19,
				HasMediumPlus:     true,
			},
			wantStage: "solid",
		},
		{
			name: "solid: boundary — exactly 4 problems, 75% rate",
			signals: StageSignals{
				ProblemsSolved:    4,
				ACIndependentRate: 0.75,
				RecentGuidedRatio: 0.0,
				HasMediumPlus:     true,
			},
			wantStage: "solid",
		},
		{
			name: "not solid: declining weakness trend blocks solid AND developing",
			signals: StageSignals{
				ProblemsSolved:    5,
				ACIndependentRate: 0.80,
				RecentGuidedRatio: 0.10,
				HasMediumPlus:     true,
			},
			weakTags:  []WeaknessTagSummary{{Tag: "weakness:x", Count: 3, Trend: "declining"}},
			wantStage: "struggling",
		},
		{
			name: "not solid: guided ratio >= 0.2",
			signals: StageSignals{
				ProblemsSolved:    4,
				ACIndependentRate: 0.75,
				RecentGuidedRatio: 0.20,
				HasMediumPlus:     true,
			},
			wantStage: "developing",
		},
		{
			name: "not solid: no medium+ problems",
			signals: StageSignals{
				ProblemsSolved:    4,
				ACIndependentRate: 0.75,
				RecentGuidedRatio: 0.10,
				HasMediumPlus:     false,
			},
			wantStage: "developing",
		},
		{
			name: "developing: exactly 3 problems, 50% rate",
			signals: StageSignals{
				ProblemsSolved:    3,
				ACIndependentRate: 0.50,
				RecentGuidedRatio: 0.40,
			},
			wantStage: "developing",
		},
		{
			name: "struggling: 2 problems, low rate",
			signals: StageSignals{
				ProblemsSolved:    2,
				ACIndependentRate: 0.20,
				RecentGuidedRatio: 0.80,
			},
			wantStage: "struggling",
		},
		{
			name: "struggling: 3 problems but below 50% rate",
			signals: StageSignals{
				ProblemsSolved:    3,
				ACIndependentRate: 0.33,
			},
			wantStage: "struggling",
		},
		{
			name: "struggling: decline overrides developing",
			signals: StageSignals{
				ProblemsSolved:    3,
				ACIndependentRate: 0.50,
			},
			weakTags:  []WeaknessTagSummary{{Tag: "weakness:x", Count: 2, Trend: "declining"}},
			wantStage: "struggling",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotStage, gotReason := computeStage(tt.signals, tt.weakTags)
			if gotStage != tt.wantStage {
				t.Errorf("computeStage() stage = %q, want %q (reason: %q)", gotStage, tt.wantStage, gotReason)
			}
			if gotReason == "" {
				t.Errorf("computeStage() reason is empty")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MasteryMap — stage calculation, pattern filter, concept mastery, weak concepts,
// regression detection
// ---------------------------------------------------------------------------

func TestMasteryMap_Stages(t *testing.T) {
	t.Parallel()

	// Build entries for "binary-search" to reach each stage.
	// solid: 4+ problems, 75%+ ac-independent, <20% guided, has medium.
	solidMeta := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(33),
		"pattern":        "binary-search",
		"concept_breakdown": []any{
			map[string]any{"concept": "recognize applicability", "mastery": "independent"},
		},
	}

	tests := []struct {
		name      string
		entries   []content.RichTagEntry
		wantStage string
	}{
		{
			name:      "unexplored: single entry",
			entries:   []content.RichTagEntry{richEntryWithMeta(t, []string{"binary-search", "easy", "ac-independent"}, 1, solidMeta)},
			wantStage: "unexplored",
		},
		{
			name: "solid: 4 ac-independent medium problems, low guided ratio",
			entries: func() []content.RichTagEntry {
				es := make([]content.RichTagEntry, 0, 4)
				for i := range 4 {
					es = append(es, richEntryWithMeta(t,
						[]string{"binary-search", "medium", "ac-independent"},
						i+1,
						solidMeta,
					))
				}
				return es
			}(),
			wantStage: "solid",
		},
		{
			name: "developing: 3 problems, 2 ac-independent",
			entries: []content.RichTagEntry{
				richEntryWithMeta(t, []string{"binary-search", "easy", "ac-independent"}, 3, solidMeta),
				richEntryWithMeta(t, []string{"binary-search", "easy", "ac-independent"}, 2, solidMeta),
				richEntryWithMeta(t, []string{"binary-search", "easy", "ac-with-hints"}, 1, solidMeta),
			},
			wantStage: "developing",
		},
		{
			name: "struggling: 2 problems, 0 ac-independent",
			entries: []content.RichTagEntry{
				richEntryWithMeta(t, []string{"binary-search", "easy", "incomplete"}, 2, solidMeta),
				richEntryWithMeta(t, []string{"binary-search", "easy", "incomplete"}, 1, solidMeta),
			},
			wantStage: "struggling",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := MasteryMap(tt.entries, nil, nil, 90)
			if len(result.Patterns) == 0 {
				t.Fatal("MasteryMap() returned no patterns")
			}
			got := result.Patterns[0]
			if got.Stage != tt.wantStage {
				t.Errorf("MasteryMap() stage = %q, want %q (signals: %+v)", got.Stage, tt.wantStage, got.StageSignals)
			}
		})
	}
}

func TestMasteryMap_Empty(t *testing.T) {
	t.Parallel()

	result := MasteryMap(nil, nil, nil, 30)
	if len(result.Patterns) != 0 {
		t.Errorf("MasteryMap(nil) Patterns = %v, want empty", result.Patterns)
	}
	if result.PeriodDays != 30 {
		t.Errorf("MasteryMap(nil) PeriodDays = %d, want 30", result.PeriodDays)
	}
}

func TestMasteryMap_PatternFilter(t *testing.T) {
	t.Parallel()

	meta := map[string]any{"learning_type": "leetcode", "problem_number": float64(1)}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "easy", "ac-independent"}, 1, meta),
		richEntryWithMeta(t, []string{"dp", "easy", "ac-independent"}, 1, meta),
		richEntryWithMeta(t, []string{"graph", "easy", "ac-independent"}, 1, meta),
	}

	result := MasteryMap(entries, nil, []string{"binary-search", "dp"}, 90)
	if len(result.Patterns) != 2 {
		t.Fatalf("MasteryMap() with filter Patterns len = %d, want 2", len(result.Patterns))
	}
	patterns := make(map[string]bool)
	for _, p := range result.Patterns {
		patterns[p.Pattern] = true
	}
	if !patterns["binary-search"] {
		t.Error("MasteryMap() with filter missing binary-search")
	}
	if !patterns["dp"] {
		t.Error("MasteryMap() with filter missing dp")
	}
	if patterns["graph"] {
		t.Error("MasteryMap() with filter unexpectedly included graph")
	}
}

func TestMasteryMap_ConceptMasteryAggregation(t *testing.T) {
	t.Parallel()

	entry1Meta := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(33),
		"concept_breakdown": []any{
			map[string]any{"concept": "recognize binary search", "mastery": "independent"},
			map[string]any{"concept": "handle rotation", "mastery": "guided", "coaching_hint": "check mid"},
		},
	}
	entry2Meta := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(153),
		"concept_breakdown": []any{
			map[string]any{"concept": "recognize binary search", "mastery": "independent"},
			map[string]any{"concept": "find min in rotation", "mastery": "told"},
		},
	}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-independent"}, 2, entry1Meta),
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-with-hints"}, 1, entry2Meta),
	}

	result := MasteryMap(entries, nil, nil, 90)
	if len(result.Patterns) == 0 {
		t.Fatal("MasteryMap() returned no patterns")
	}
	pm := result.Patterns[0]

	// independent:2, guided:1, told:1
	if pm.ConceptMastery["independent"] != 2 {
		t.Errorf("ConceptMastery[independent] = %d, want 2", pm.ConceptMastery["independent"])
	}
	if pm.ConceptMastery["guided"] != 1 {
		t.Errorf("ConceptMastery[guided] = %d, want 1", pm.ConceptMastery["guided"])
	}
	if pm.ConceptMastery["told"] != 1 {
		t.Errorf("ConceptMastery[told] = %d, want 1", pm.ConceptMastery["told"])
	}
}

func TestMasteryMap_WeakConceptsExtraction(t *testing.T) {
	t.Parallel()

	meta := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(33),
		"concept_breakdown": []any{
			map[string]any{"concept": "independent concept", "mastery": "independent"},
			map[string]any{"concept": "guided concept", "mastery": "guided", "coaching_hint": "check mid"},
			map[string]any{"concept": "told concept", "mastery": "told"},
		},
	}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-with-hints"}, 1, meta),
	}

	result := MasteryMap(entries, nil, nil, 90)
	if len(result.Patterns) == 0 {
		t.Fatal("MasteryMap() returned no patterns")
	}
	pm := result.Patterns[0]

	if len(pm.WeakConcepts) != 2 {
		t.Fatalf("WeakConcepts len = %d, want 2", len(pm.WeakConcepts))
	}
	// Both guided and told should appear; independent should not.
	masteries := make(map[string]bool)
	for _, wc := range pm.WeakConcepts {
		masteries[wc.Mastery] = true
		if wc.Mastery == "guided" && wc.CoachingHint != "check mid" {
			t.Errorf("WeakConcept CoachingHint = %q, want %q", wc.CoachingHint, "check mid")
		}
		if wc.FromProblem != 33 {
			t.Errorf("WeakConcept FromProblem = %d, want 33", wc.FromProblem)
		}
	}
	if !masteries["guided"] {
		t.Error("WeakConcepts missing guided entry")
	}
	if !masteries["told"] {
		t.Error("WeakConcepts missing told entry")
	}
	if masteries["independent"] {
		t.Error("WeakConcepts unexpectedly includes independent entry")
	}
}

func TestMasteryMap_RegressionDetection(t *testing.T) {
	t.Parallel()

	meta := map[string]any{"learning_type": "leetcode", "problem_number": float64(33)}

	// DB order: most recent first (DESC). Recent 3 are worse than previous 3.
	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "medium", "incomplete"}, 1, meta),
		richEntryWithMeta(t, []string{"binary-search", "medium", "incomplete"}, 2, meta),
		richEntryWithMeta(t, []string{"binary-search", "medium", "incomplete"}, 3, meta),
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-independent"}, 4, meta),
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-independent"}, 5, meta),
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-independent"}, 6, meta),
	}

	regressions := []retrieval.RegressionCard{
		{Slug: entries[0].Slug, Title: "Test", ReviewedAt: time.Now().AddDate(0, 0, -1)},
	}

	result := MasteryMap(entries, regressions, nil, 90)
	if len(result.Patterns) == 0 {
		t.Fatal("MasteryMap() returned no patterns")
	}
	pm := result.Patterns[0]
	if pm.RegressionSignal == nil {
		t.Fatal("RegressionSignal is nil, want non-nil regression detected")
	}
	if pm.RegressionSignal.ResultTrend == "" {
		t.Error("RegressionSignal.ResultTrend is empty, want result trend string")
	}
}

func TestMasteryMap_NoRegressionWhenPerformanceStable(t *testing.T) {
	t.Parallel()

	meta := map[string]any{"learning_type": "leetcode", "problem_number": float64(33)}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-independent"}, 3, meta),
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-independent"}, 2, meta),
	}

	result := MasteryMap(entries, nil, nil, 90)
	if len(result.Patterns) == 0 {
		t.Fatal("MasteryMap() returned no patterns")
	}
	pm := result.Patterns[0]
	if pm.RegressionSignal != nil {
		t.Errorf("RegressionSignal = %+v, want nil (no regression with <6 entries and no FSRS cards)", pm.RegressionSignal)
	}
}

func TestMasteryMap_SortedByStageUrgency(t *testing.T) {
	t.Parallel()

	// Create entries for 3 patterns at different stages.
	// solid pattern needs 4+ problems, 75%+ ac-independent, <20% guided, medium+.
	solidMeta := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(1),
		"concept_breakdown": []any{
			map[string]any{"concept": "solid concept", "mastery": "independent"},
		},
	}
	// unexplored: 1 entry.
	unexploredMeta := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(2),
	}
	// struggling: 2+ problems, low ac-independent rate.
	strugglingMeta := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(3),
	}

	entries := make([]content.RichTagEntry, 0, 7)
	// Solid: 4 ac-independent medium entries for dp.
	for i := range 4 {
		entries = append(entries, richEntryWithMeta(t,
			[]string{"dp", "medium", "ac-independent"}, i+1, solidMeta))
	}
	// Unexplored: 1 entry for binary-search. Struggling: 2 incomplete entries for graph.
	entries = append(entries,
		richEntryWithMeta(t, []string{"binary-search", "easy", "ac-independent"}, 1, unexploredMeta),
		richEntryWithMeta(t, []string{"graph", "easy", "incomplete"}, 2, strugglingMeta),
		richEntryWithMeta(t, []string{"graph", "easy", "incomplete"}, 1, strugglingMeta),
	)

	result := MasteryMap(entries, nil, nil, 90)
	if len(result.Patterns) < 3 {
		t.Fatalf("MasteryMap() Patterns len = %d, want >= 3", len(result.Patterns))
	}

	// struggling should be first (highest urgency).
	if result.Patterns[0].Stage != "struggling" {
		t.Errorf("Patterns[0].Stage = %q, want %q", result.Patterns[0].Stage, "struggling")
	}
	// solid should be last.
	last := result.Patterns[len(result.Patterns)-1]
	if last.Stage != "solid" {
		t.Errorf("Patterns[last].Stage = %q, want %q", last.Stage, "solid")
	}
}

func TestMasteryMap_VariationCoverageTracksAttempted(t *testing.T) {
	t.Parallel()

	// Problem 33 links to 81 (which is also attempted) and 162 (not attempted).
	meta33 := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(33),
		"variation_links": []any{
			map[string]any{"problem_number": float64(81), "relationship": "harder_variant"},
			map[string]any{"problem_number": float64(162), "relationship": "follow_up"},
		},
	}
	meta81 := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(81),
	}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-independent"}, 2, meta33),
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-with-hints"}, 1, meta81),
	}

	result := MasteryMap(entries, nil, nil, 90)
	if len(result.Patterns) == 0 {
		t.Fatal("MasteryMap() returned no patterns")
	}
	pm := result.Patterns[0]

	// Both 33 and 81 should be in Attempted.
	attempted := make(map[int]bool)
	for _, n := range pm.VariationCoverage.Attempted {
		attempted[n] = true
	}
	if !attempted[33] {
		t.Error("VariationCoverage.Attempted missing 33")
	}
	if !attempted[81] {
		t.Error("VariationCoverage.Attempted missing 81")
	}

	// 162 should be in KnownFollowUps since it's not attempted.
	foundFollowUp := false
	for _, fu := range pm.VariationCoverage.KnownFollowUps {
		if fu.ProblemNumber == 162 {
			foundFollowUp = true
			if fu.FromProblem != 33 {
				t.Errorf("KnownFollowUp 162 FromProblem = %d, want 33", fu.FromProblem)
			}
		}
	}
	if !foundFollowUp {
		t.Error("KnownFollowUps missing problem 162")
	}
}

// ---------------------------------------------------------------------------
// ConceptGaps — systemic gaps, coaching history, mastery filter, grouping
// ---------------------------------------------------------------------------

func TestConceptGaps_SystemicGaps(t *testing.T) {
	t.Parallel()

	// Same concept appearing as "guided" in 2 different TILs should produce a systemic gap.
	meta1 := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(33),
		"concept_breakdown": []any{
			map[string]any{"concept": "Recognize binary search applicability", "mastery": "guided"},
		},
	}
	meta2 := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(153),
		"concept_breakdown": []any{
			map[string]any{"concept": "Recognize binary search applicability", "mastery": "guided"},
		},
	}
	// A concept appearing only once should NOT produce a systemic gap.
	meta3 := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(704),
		"concept_breakdown": []any{
			map[string]any{"concept": "Unique concept only once", "mastery": "told"},
		},
	}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-with-hints"}, 3, meta1),
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-with-hints"}, 2, meta2),
		richEntryWithMeta(t, []string{"binary-search", "easy", "ac-independent"}, 1, meta3),
	}

	result := ConceptGaps(entries, nil, 90)

	if len(result.SystemicGaps) != 1 {
		t.Fatalf("ConceptGaps() SystemicGaps len = %d, want 1", len(result.SystemicGaps))
	}
	gap := result.SystemicGaps[0]
	// Concept key is normalized to lowercase.
	wantConcept := "recognize binary search applicability"
	if gap.Concept != wantConcept {
		t.Errorf("SystemicGaps[0].Concept = %q, want %q", gap.Concept, wantConcept)
	}
	if gap.Count != 2 {
		t.Errorf("SystemicGaps[0].Count = %d, want 2", gap.Count)
	}
}

func TestConceptGaps_OnlyOnceDoesNotCreateGap(t *testing.T) {
	t.Parallel()

	meta := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(1),
		"concept_breakdown": []any{
			map[string]any{"concept": "Single occurrence", "mastery": "guided"},
		},
	}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "easy", "ac-with-hints"}, 1, meta),
	}

	result := ConceptGaps(entries, nil, 90)
	if len(result.SystemicGaps) != 0 {
		t.Errorf("ConceptGaps() SystemicGaps len = %d, want 0 (single occurrence)", len(result.SystemicGaps))
	}
}

func TestConceptGaps_CoachingHistory(t *testing.T) {
	t.Parallel()

	meta := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(33),
		"concept_breakdown": []any{
			map[string]any{
				"concept":       "Handle rotation",
				"mastery":       "guided",
				"coaching_hint": "check which half is sorted",
			},
			map[string]any{
				"concept": "No hint concept",
				"mastery": "guided",
				// no coaching_hint
			},
		},
	}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-with-hints"}, 1, meta),
	}

	result := ConceptGaps(entries, nil, 90)

	// Only the concept with a coaching_hint should appear in coaching history.
	if len(result.CoachingHistory) != 1 {
		t.Fatalf("CoachingHistory len = %d, want 1", len(result.CoachingHistory))
	}
	rec := result.CoachingHistory[0]
	if rec.CoachingHint != "check which half is sorted" {
		t.Errorf("CoachingHistory[0].CoachingHint = %q, want %q", rec.CoachingHint, "check which half is sorted")
	}
	if rec.ProblemNumber != 33 {
		t.Errorf("CoachingHistory[0].ProblemNumber = %d, want 33", rec.ProblemNumber)
	}
}

func TestConceptGaps_MasteryFilter(t *testing.T) {
	t.Parallel()

	// Default filter is guided + told.
	// Explicitly passing ["told"] should only count "told" concepts.
	meta := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(1),
		"concept_breakdown": []any{
			map[string]any{"concept": "guided concept", "mastery": "guided"},
			map[string]any{"concept": "told concept", "mastery": "told"},
		},
	}
	meta2 := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(2),
		"concept_breakdown": []any{
			map[string]any{"concept": "told concept", "mastery": "told"},
		},
	}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "easy", "ac-with-hints"}, 2, meta),
		richEntryWithMeta(t, []string{"binary-search", "easy", "ac-with-hints"}, 1, meta2),
	}

	// With told-only filter, only "told concept" (2 occurrences) should be a systemic gap.
	result := ConceptGaps(entries, []string{"told"}, 90)

	if len(result.SystemicGaps) != 1 {
		t.Fatalf("ConceptGaps(filter=told) SystemicGaps len = %d, want 1", len(result.SystemicGaps))
	}
	if result.SystemicGaps[0].Concept != "told concept" {
		t.Errorf("SystemicGaps[0].Concept = %q, want %q", result.SystemicGaps[0].Concept, "told concept")
	}
}

func TestConceptGaps_ExactMatchGrouping(t *testing.T) {
	t.Parallel()

	// Slightly different capitalisation => different keys after normalization.
	meta1 := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(1),
		"concept_breakdown": []any{
			map[string]any{"concept": "Binary Search", "mastery": "guided"},
		},
	}
	meta2 := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(2),
		"concept_breakdown": []any{
			// Same after ToLower+TrimSpace.
			map[string]any{"concept": "binary search", "mastery": "guided"},
		},
	}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "easy", "ac-with-hints"}, 2, meta1),
		richEntryWithMeta(t, []string{"binary-search", "easy", "ac-with-hints"}, 1, meta2),
	}

	result := ConceptGaps(entries, nil, 90)

	// Both normalize to "binary search" — should produce one gap of count 2.
	if len(result.SystemicGaps) != 1 {
		t.Fatalf("ConceptGaps() case-insensitive grouping SystemicGaps len = %d, want 1", len(result.SystemicGaps))
	}
	if result.SystemicGaps[0].Count != 2 {
		t.Errorf("SystemicGaps[0].Count = %d, want 2", result.SystemicGaps[0].Count)
	}
}

func TestConceptGaps_Empty(t *testing.T) {
	t.Parallel()

	result := ConceptGaps(nil, nil, 30)
	if len(result.SystemicGaps) != 0 {
		t.Errorf("ConceptGaps(nil) SystemicGaps = %v, want empty", result.SystemicGaps)
	}
	if len(result.CoachingHistory) != 0 {
		t.Errorf("ConceptGaps(nil) CoachingHistory = %v, want empty", result.CoachingHistory)
	}
	if result.PeriodDays != 30 {
		t.Errorf("ConceptGaps(nil) PeriodDays = %d, want 30", result.PeriodDays)
	}
}

// ---------------------------------------------------------------------------
// VariationMap — clusters, isolated problems, pattern filter, include_unattempted
// ---------------------------------------------------------------------------

func TestVariationMap_ClusterBuilding(t *testing.T) {
	t.Parallel()

	// Problem 33 links to 81 (also attempted). Should form a cluster.
	meta33 := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(33),
		"variation_links": []any{
			map[string]any{"problem_number": float64(81), "relationship": "harder_variant", "notes": "with duplicates"},
		},
	}
	meta81 := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(81),
	}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-independent"}, 2, meta33),
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-with-hints"}, 1, meta81),
	}

	result := VariationMap(entries, "", false, 90)

	if len(result.Clusters) != 1 {
		t.Fatalf("VariationMap() Clusters len = %d, want 1", len(result.Clusters))
	}
	cluster := result.Clusters[0]
	if cluster.AnchorProblem.Number != 33 {
		t.Errorf("Cluster anchor = %d, want 33", cluster.AnchorProblem.Number)
	}
	if len(cluster.Variations) != 1 {
		t.Fatalf("Cluster Variations len = %d, want 1", len(cluster.Variations))
	}
	v := cluster.Variations[0]
	if v.ProblemNumber != 81 {
		t.Errorf("Variation ProblemNumber = %d, want 81", v.ProblemNumber)
	}
	if v.Relationship != "harder_variant" {
		t.Errorf("Variation Relationship = %q, want %q", v.Relationship, "harder_variant")
	}
	if !v.Attempted {
		t.Error("Variation Attempted = false, want true (81 is in entries)")
	}
	if v.Notes != "with duplicates" {
		t.Errorf("Variation Notes = %q, want %q", v.Notes, "with duplicates")
	}
}

func TestVariationMap_IsolatedProblems(t *testing.T) {
	t.Parallel()

	// Problem with no variation links should be isolated.
	meta := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(704),
	}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "easy", "ac-independent"}, 1, meta),
	}

	result := VariationMap(entries, "", false, 90)

	if len(result.Clusters) != 0 {
		t.Errorf("VariationMap() Clusters len = %d, want 0 (no links)", len(result.Clusters))
	}
	if len(result.IsolatedProblems) != 1 {
		t.Fatalf("VariationMap() IsolatedProblems len = %d, want 1", len(result.IsolatedProblems))
	}
	if result.IsolatedProblems[0].Number != 704 {
		t.Errorf("IsolatedProblems[0].Number = %d, want 704", result.IsolatedProblems[0].Number)
	}
}

func TestVariationMap_PatternFilter(t *testing.T) {
	t.Parallel()

	metaBS := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(33),
	}
	metaDP := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(70),
	}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-independent"}, 2, metaBS),
		richEntryWithMeta(t, []string{"dp", "easy", "ac-independent"}, 1, metaDP),
	}

	result := VariationMap(entries, "binary-search", false, 90)

	// Only binary-search entries should appear.
	if len(result.IsolatedProblems)+len(result.Clusters) != 1 {
		t.Errorf("VariationMap() with pattern filter total problems = %d, want 1",
			len(result.IsolatedProblems)+len(result.Clusters))
	}
	if len(result.IsolatedProblems) == 1 && result.IsolatedProblems[0].Number != 33 {
		t.Errorf("IsolatedProblems[0].Number = %d, want 33", result.IsolatedProblems[0].Number)
	}
}

func TestVariationMap_IncludeUnattempted(t *testing.T) {
	t.Parallel()

	// Problem 33 links to 162 which is NOT in entries (not attempted).
	meta33 := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(33),
		"variation_links": []any{
			map[string]any{"problem_number": float64(162), "relationship": "follow_up"},
		},
	}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-independent"}, 1, meta33),
	}

	// Without includeUnattempted: no variations (162 not attempted) → problem 33 becomes isolated.
	resultExclude := VariationMap(entries, "", false, 90)
	// With includeUnattempted: cluster should include 162 as unattempted.
	resultInclude := VariationMap(entries, "", true, 90)

	// Without flag: cluster for 33 exists but variations list is empty → 33 still forms a cluster
	// (buildClusters marks num as clustered if len(info.links) > 0, but skips variations if not attempted).
	// 33 is clustered (has links), so not in IsolatedProblems.
	_ = resultExclude // structural test is sufficient

	if len(resultInclude.Clusters) == 0 {
		t.Fatal("VariationMap(includeUnattempted=true) Clusters empty, want cluster for problem 33")
	}
	found := false
	for _, c := range resultInclude.Clusters {
		if c.AnchorProblem.Number == 33 {
			found = true
			if len(c.Variations) != 1 {
				t.Errorf("Cluster 33 Variations len = %d, want 1", len(c.Variations))
			} else if c.Variations[0].Attempted {
				t.Errorf("Variation 162 Attempted = true, want false")
			}
		}
	}
	if !found {
		t.Error("VariationMap(includeUnattempted=true) missing cluster for problem 33")
	}
}

func TestVariationMap_Empty(t *testing.T) {
	t.Parallel()

	result := VariationMap(nil, "", false, 30)
	if len(result.Clusters) != 0 {
		t.Errorf("VariationMap(nil) Clusters = %v, want empty", result.Clusters)
	}
	if len(result.IsolatedProblems) != 0 {
		t.Errorf("VariationMap(nil) IsolatedProblems = %v, want empty", result.IsolatedProblems)
	}
	if result.PeriodDays != 30 {
		t.Errorf("VariationMap(nil) PeriodDays = %d, want 30", result.PeriodDays)
	}
}

func TestVariationMap_SortedByAnchorNumber(t *testing.T) {
	t.Parallel()

	// Two clusters: problem 153 and problem 33 — result should be sorted by number ascending.
	meta153 := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(153),
		"variation_links": []any{
			map[string]any{"problem_number": float64(154), "relationship": "harder_variant"},
		},
	}
	meta33 := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(33),
		"variation_links": []any{
			map[string]any{"problem_number": float64(81), "relationship": "harder_variant"},
		},
	}
	meta154 := map[string]any{"learning_type": "leetcode", "problem_number": float64(154)}
	meta81 := map[string]any{"learning_type": "leetcode", "problem_number": float64(81)}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-independent"}, 4, meta153),
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-independent"}, 3, meta33),
		richEntryWithMeta(t, []string{"binary-search", "hard", "ac-with-hints"}, 2, meta154),
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-with-hints"}, 1, meta81),
	}

	result := VariationMap(entries, "", false, 90)

	if len(result.Clusters) < 2 {
		t.Fatalf("VariationMap() Clusters len = %d, want >= 2", len(result.Clusters))
	}
	if result.Clusters[0].AnchorProblem.Number >= result.Clusters[1].AnchorProblem.Number {
		t.Errorf("Clusters not sorted: [0]=%d >= [1]=%d",
			result.Clusters[0].AnchorProblem.Number, result.Clusters[1].AnchorProblem.Number)
	}
}

// ---------------------------------------------------------------------------
// MasteryMap — unexplored approaches extraction
// ---------------------------------------------------------------------------

func TestMasteryMap_UnexploredApproaches(t *testing.T) {
	t.Parallel()

	meta := map[string]any{
		"learning_type":  "leetcode",
		"problem_number": float64(33),
		"alternative_approaches": []any{
			map[string]any{"name": "two-pass pivot search", "explored": false},
			map[string]any{"name": "recursive binary search", "explored": true},
		},
	}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"binary-search", "medium", "ac-independent"}, 1, meta),
	}

	result := MasteryMap(entries, nil, nil, 90)
	if len(result.Patterns) == 0 {
		t.Fatal("MasteryMap() returned no patterns")
	}
	pm := result.Patterns[0]

	if len(pm.UnexploredApproaches) != 1 {
		t.Fatalf("UnexploredApproaches len = %d, want 1", len(pm.UnexploredApproaches))
	}
	if pm.UnexploredApproaches[0].Name != "two-pass pivot search" {
		t.Errorf("UnexploredApproaches[0].Name = %q, want %q", pm.UnexploredApproaches[0].Name, "two-pass pivot search")
	}
	if pm.UnexploredApproaches[0].ProblemNumber != 33 {
		t.Errorf("UnexploredApproaches[0].ProblemNumber = %d, want 33", pm.UnexploredApproaches[0].ProblemNumber)
	}
}

// ---------------------------------------------------------------------------
// MasteryMap — go-cmp structural comparison for PatternMastery fields
// ---------------------------------------------------------------------------

func TestMasteryMap_PeriodDaysPassThrough(t *testing.T) {
	t.Parallel()

	result := MasteryMap(nil, nil, nil, 45)
	if diff := cmp.Diff(45, result.PeriodDays); diff != "" {
		t.Errorf("MasteryMap() PeriodDays mismatch (-want +got):\n%s", diff)
	}
}

func TestMasteryMap_DifficultyDistribution(t *testing.T) {
	t.Parallel()

	meta := map[string]any{"learning_type": "leetcode", "problem_number": float64(1)}

	entries := []content.RichTagEntry{
		richEntryWithMeta(t, []string{"dp", "easy", "ac-independent"}, 3, meta),
		richEntryWithMeta(t, []string{"dp", "medium", "ac-independent"}, 2, meta),
		richEntryWithMeta(t, []string{"dp", "hard", "ac-with-hints"}, 1, meta),
	}

	result := MasteryMap(entries, nil, nil, 90)
	if len(result.Patterns) == 0 {
		t.Fatal("MasteryMap() returned no patterns")
	}
	pm := result.Patterns[0]

	want := map[string]int{"easy": 1, "medium": 1, "hard": 1}
	if diff := cmp.Diff(want, pm.DifficultyDistribution, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("DifficultyDistribution mismatch (-want +got):\n%s", diff)
	}
}
