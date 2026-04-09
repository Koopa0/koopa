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

	tests := []struct {
		name                           string
		weakness, improvement, mastery int64
		want                           MasteryStage
	}{
		{name: "weakness only", weakness: 3, improvement: 0, mastery: 0, want: StageStruggling},
		{name: "single weakness", weakness: 1, improvement: 0, mastery: 0, want: StageStruggling},
		{name: "improvement kicks in", weakness: 2, improvement: 1, mastery: 0, want: StageDeveloping},
		{name: "mixed mastery and weakness", weakness: 2, improvement: 0, mastery: 1, want: StageDeveloping},
		{name: "improvement without mastery", weakness: 0, improvement: 3, mastery: 0, want: StageDeveloping},
		{name: "mastery dominates", weakness: 1, improvement: 0, mastery: 3, want: StageSolid},
		{name: "pure mastery", weakness: 0, improvement: 0, mastery: 5, want: StageSolid},
		{name: "single mastery beats zero weakness", weakness: 0, improvement: 0, mastery: 1, want: StageSolid},
		{name: "tie between mastery and weakness — developing not solid", weakness: 2, improvement: 0, mastery: 2, want: StageDeveloping},
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
