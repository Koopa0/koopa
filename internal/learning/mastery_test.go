package learning

import (
	"testing"
)

func TestDeriveMasteryStage(t *testing.T) {
	t.Parallel()

	// Cases are organized by which heuristic rule they exercise. The
	// MinObservationsForVerdict floor (rule 1) catches every case with
	// total < 3 — that's the most important property and the test must
	// verify it before any of the ratio rules.
	tests := []struct {
		name                           string
		weakness, improvement, mastery int64
		want                           MasteryStage
	}{
		// --- Rule 1: insufficient data → developing ---
		{name: "zero observations", weakness: 0, improvement: 0, mastery: 0, want: StageDeveloping},
		{name: "single weakness — was struggling, now developing (insufficient data floor)", weakness: 1, improvement: 0, mastery: 0, want: StageDeveloping},
		{name: "single mastery — was solid, now developing (insufficient data floor)", weakness: 0, improvement: 0, mastery: 1, want: StageDeveloping},
		{name: "two weaknesses still under floor", weakness: 2, improvement: 0, mastery: 0, want: StageDeveloping},
		{name: "two masteries still under floor", weakness: 0, improvement: 0, mastery: 2, want: StageDeveloping},
		{name: "1+1 mixed under floor", weakness: 1, improvement: 0, mastery: 1, want: StageDeveloping},

		// --- Rule 2: solid (mastery>=2 AND mastery>=2*weakness) ---
		{name: "pure mastery, three", weakness: 0, improvement: 0, mastery: 3, want: StageSolid},
		{name: "pure mastery, five", weakness: 0, improvement: 0, mastery: 5, want: StageSolid},
		{name: "mastery doubles weakness exactly", weakness: 2, improvement: 0, mastery: 4, want: StageSolid},
		{name: "mastery triples weakness", weakness: 1, improvement: 1, mastery: 4, want: StageSolid},

		// --- Rule 3: struggling (weakness>=2 AND weakness>mastery) ---
		{name: "pure weakness, three", weakness: 3, improvement: 0, mastery: 0, want: StageStruggling},
		{name: "weakness dominates 4-1", weakness: 4, improvement: 0, mastery: 1, want: StageStruggling},
		{name: "weakness dominates with improvement bystander", weakness: 3, improvement: 1, mastery: 0, want: StageStruggling},

		// --- Rule 4: developing (mixed signal above floor) ---
		{name: "audit case: 4 mastery + 3 weakness → developing (signal mixed)", weakness: 3, improvement: 0, mastery: 4, want: StageDeveloping},
		{name: "tie 2-2 → developing (neither rule fires)", weakness: 2, improvement: 0, mastery: 2, want: StageDeveloping},
		{name: "improvement-led progression", weakness: 1, improvement: 3, mastery: 1, want: StageDeveloping},
		{name: "almost solid but not quite (mastery 3 vs weakness 2)", weakness: 2, improvement: 0, mastery: 3, want: StageDeveloping},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := DeriveMasteryStage(tt.weakness, tt.improvement, tt.mastery)
			if got != tt.want {
				t.Errorf("DeriveMasteryStage(w=%d, i=%d, m=%d) = %q, want %q",
					tt.weakness, tt.improvement, tt.mastery, got, tt.want)
			}
		})
	}
}

func TestAggregateMasteryByDomain(t *testing.T) {
	t.Parallel()

	rows := []ConceptMasteryRow{
		{Domain: "leetcode", WeaknessCount: 0, ImprovementCount: 0, MasteryCount: 5}, // solid
		{Domain: "leetcode", WeaknessCount: 4, ImprovementCount: 0, MasteryCount: 0}, // struggling
		{Domain: "leetcode", WeaknessCount: 1, ImprovementCount: 1, MasteryCount: 1}, // developing (under floor)
		{Domain: "japanese", WeaknessCount: 0, ImprovementCount: 0, MasteryCount: 3}, // solid
		{Domain: "japanese", WeaknessCount: 0, ImprovementCount: 1, MasteryCount: 0}, // developing (under floor)
	}

	got := AggregateMasteryByDomain(rows)

	if len(got) != 2 {
		t.Fatalf("AggregateMasteryByDomain() returned %d domains, want 2", len(got))
	}

	// First domain should be leetcode (insertion order).
	lc := got[0]
	if lc.Domain != "leetcode" {
		t.Fatalf("got[0].Domain = %q, want %q", lc.Domain, "leetcode")
	}
	if lc.ConceptsTotal != 3 || lc.ConceptsMastered != 1 || lc.ConceptsWeak != 1 || lc.ConceptsDeveloping != 1 {
		t.Errorf("leetcode = {total:%d, mastered:%d, weak:%d, developing:%d}, want {3,1,1,1}",
			lc.ConceptsTotal, lc.ConceptsMastered, lc.ConceptsWeak, lc.ConceptsDeveloping)
	}

	jp := got[1]
	if jp.Domain != "japanese" {
		t.Fatalf("got[1].Domain = %q, want %q", jp.Domain, "japanese")
	}
	if jp.ConceptsTotal != 2 || jp.ConceptsMastered != 1 || jp.ConceptsWeak != 0 || jp.ConceptsDeveloping != 1 {
		t.Errorf("japanese = {total:%d, mastered:%d, weak:%d, developing:%d}, want {2,1,0,1}",
			jp.ConceptsTotal, jp.ConceptsMastered, jp.ConceptsWeak, jp.ConceptsDeveloping)
	}
}
