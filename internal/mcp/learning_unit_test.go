package mcp

import (
	"testing"
)

func TestClampDurationMinutes(t *testing.T) {
	t.Parallel()

	flex := func(n int) *FlexInt {
		v := FlexInt(n)
		return &v
	}
	i32 := func(n int32) *int32 { return &n }

	tests := []struct {
		name string
		in   *FlexInt
		want *int32
	}{
		{name: "nil input", in: nil, want: nil},
		{name: "zero", in: flex(0), want: nil},
		{name: "negative one — was silently becoming 1 minute before fix", in: flex(-1), want: nil},
		{name: "large negative", in: flex(-9999), want: nil},
		{name: "lower bound", in: flex(1), want: i32(1)},
		{name: "typical session length", in: flex(45), want: i32(45)},
		{name: "upper bound", in: flex(1440), want: i32(1440)},
		{name: "above cap clamps to 1440", in: flex(1441), want: i32(1440)},
		{name: "absurd value clamps to 1440", in: flex(99999), want: i32(1440)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := clampDurationMinutes(tt.in)
			switch {
			case tt.want == nil && got == nil:
				// match
			case tt.want == nil && got != nil:
				t.Fatalf("clampDurationMinutes(%v) = %d, want nil", tt.in, *got)
			case tt.want != nil && got == nil:
				t.Fatalf("clampDurationMinutes(%v) = nil, want %d", tt.in, *tt.want)
			case *tt.want != *got:
				t.Errorf("clampDurationMinutes(%v) = %d, want %d", tt.in, *got, *tt.want)
			}
		})
	}
}

func TestDeriveMasteryStage(t *testing.T) {
	t.Parallel()

	// Cases are organized by which heuristic rule they exercise. The
	// minObservationsForVerdict floor (rule 1) catches every case with
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
		// The audit's specific case: 4 mastery + 3 weakness. mastery >= 2
		// but mastery (4) is not >= 2*weakness (6), and weakness (3) is
		// not > mastery (4). Falls through to developing — "data sufficient
		// but signal mixed, still learning". This is the canonical test
		// case for the heuristic doing what the human intuitively wants.
		{name: "audit case: 4 mastery + 3 weakness → developing (signal mixed)", weakness: 3, improvement: 0, mastery: 4, want: StageDeveloping},
		{name: "tie 2-2 → developing (neither rule fires)", weakness: 2, improvement: 0, mastery: 2, want: StageDeveloping},
		{name: "improvement-led progression", weakness: 1, improvement: 3, mastery: 1, want: StageDeveloping},
		{name: "almost solid but not quite (mastery 3 vs weakness 2)", weakness: 2, improvement: 0, mastery: 3, want: StageDeveloping},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := deriveMasteryStage(tt.weakness, tt.improvement, tt.mastery)
			if got != tt.want {
				t.Errorf("deriveMasteryStage(w=%d, i=%d, m=%d) = %q, want %q",
					tt.weakness, tt.improvement, tt.mastery, got, tt.want)
			}
		})
	}
}
