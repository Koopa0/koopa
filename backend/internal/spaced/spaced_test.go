package spaced

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestSM2(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   SM2Input
		want SM2Output
	}{
		{
			name: "first correct review (quality 4)",
			in:   SM2Input{Quality: 4, Repetitions: 0, EasinessFactor: 2.5, IntervalDays: 0},
			want: SM2Output{Repetitions: 1, EasinessFactor: 2.5, IntervalDays: 1},
		},
		{
			name: "second correct review (quality 4)",
			in:   SM2Input{Quality: 4, Repetitions: 1, EasinessFactor: 2.5, IntervalDays: 1},
			want: SM2Output{Repetitions: 2, EasinessFactor: 2.5, IntervalDays: 6},
		},
		{
			name: "third correct review (quality 5)",
			in:   SM2Input{Quality: 5, Repetitions: 2, EasinessFactor: 2.5, IntervalDays: 6},
			want: SM2Output{Repetitions: 3, EasinessFactor: 2.6, IntervalDays: 16},
		},
		{
			name: "third correct review (quality 3)",
			in:   SM2Input{Quality: 3, Repetitions: 2, EasinessFactor: 2.5, IntervalDays: 6},
			want: SM2Output{Repetitions: 3, EasinessFactor: 2.36, IntervalDays: 14},
		},
		{
			name: "incorrect review resets repetitions",
			in:   SM2Input{Quality: 2, Repetitions: 5, EasinessFactor: 2.5, IntervalDays: 30},
			want: SM2Output{Repetitions: 0, EasinessFactor: 2.18, IntervalDays: 1},
		},
		{
			name: "quality 0 — blackout",
			in:   SM2Input{Quality: 0, Repetitions: 3, EasinessFactor: 2.5, IntervalDays: 15},
			want: SM2Output{Repetitions: 0, EasinessFactor: 1.7, IntervalDays: 1},
		},
		{
			name: "easiness factor clamped to minimum",
			in:   SM2Input{Quality: 0, Repetitions: 0, EasinessFactor: 1.3, IntervalDays: 1},
			want: SM2Output{Repetitions: 0, EasinessFactor: 1.3, IntervalDays: 1},
		},
		{
			name: "quality clamped below 0",
			in:   SM2Input{Quality: -1, Repetitions: 0, EasinessFactor: 2.5, IntervalDays: 0},
			want: SM2Output{Repetitions: 0, EasinessFactor: 1.7, IntervalDays: 1},
		},
		{
			name: "quality clamped above 5",
			in:   SM2Input{Quality: 6, Repetitions: 0, EasinessFactor: 2.5, IntervalDays: 0},
			want: SM2Output{Repetitions: 1, EasinessFactor: 2.6, IntervalDays: 1},
		},
		{
			name: "perfect score increases EF",
			in:   SM2Input{Quality: 5, Repetitions: 0, EasinessFactor: 2.5, IntervalDays: 0},
			want: SM2Output{Repetitions: 1, EasinessFactor: 2.6, IntervalDays: 1},
		},
	}

	approxFloat := cmpopts.EquateApprox(0, 0.01)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := SM2(tt.in)
			if diff := cmp.Diff(tt.want, got, approxFloat); diff != "" {
				t.Errorf("SM2() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
