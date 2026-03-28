package mcp

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestAssessOnTrack(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		tasksCompleted int64
		weeklyRate     float64
		daysRemaining  int
		want           string
	}{
		{
			name:           "on track: tasks done and good weekly rate",
			tasksCompleted: 10,
			weeklyRate:     2.5,
			daysRemaining:  30,
			want:           "on_track",
		},
		{
			name:           "off track: zero tasks with deadline under 60 days",
			tasksCompleted: 0,
			weeklyRate:     0,
			daysRemaining:  30,
			want:           "off_track",
		},
		{
			name:           "off track: zero tasks with deadline exactly 1 day",
			tasksCompleted: 0,
			weeklyRate:     0,
			daysRemaining:  1,
			want:           "off_track",
		},
		{
			name:           "off track: zero tasks with deadline exactly 59 days",
			tasksCompleted: 0,
			weeklyRate:     0,
			daysRemaining:  59,
			want:           "off_track",
		},
		{
			name:           "at risk: zero tasks and deadline >= 60 days",
			tasksCompleted: 0,
			weeklyRate:     0,
			daysRemaining:  60,
			want:           "at_risk",
		},
		{
			name:           "at risk: zero tasks and far deadline",
			tasksCompleted: 0,
			weeklyRate:     0,
			daysRemaining:  365,
			want:           "at_risk",
		},
		{
			name:           "at risk: zero tasks and no deadline (daysRemaining zero)",
			tasksCompleted: 0,
			weeklyRate:     0,
			daysRemaining:  0,
			want:           "at_risk",
		},
		{
			name:           "at risk: low weekly rate with deadline under 90 days",
			tasksCompleted: 1,
			weeklyRate:     0.5,
			daysRemaining:  45,
			want:           "at_risk",
		},
		{
			name:           "at risk: weekly rate exactly 0.9 with deadline under 90 days",
			tasksCompleted: 1,
			weeklyRate:     0.9,
			daysRemaining:  89,
			want:           "at_risk",
		},
		{
			name:           "on track: weekly rate exactly 1.0 with deadline under 90 days",
			tasksCompleted: 1,
			weeklyRate:     1.0,
			daysRemaining:  45,
			want:           "on_track",
		},
		{
			name:           "on track: low weekly rate but deadline >= 90 days",
			tasksCompleted: 1,
			weeklyRate:     0.5,
			daysRemaining:  90,
			want:           "on_track",
		},
		{
			name:           "on track: low weekly rate and no deadline",
			tasksCompleted: 1,
			weeklyRate:     0.1,
			daysRemaining:  0,
			want:           "on_track",
		},
		{
			name:           "on track: completed goal (zero days remaining, tasks done)",
			tasksCompleted: 5,
			weeklyRate:     1.5,
			daysRemaining:  0,
			want:           "on_track",
		},
		{
			// daysRemaining < 0 means past deadline; condition requires daysRemaining > 0,
			// so this falls to at_risk, not off_track.
			name:           "at risk: zero progress with negative days remaining (past deadline)",
			tasksCompleted: 0,
			weeklyRate:     0,
			daysRemaining:  -1,
			want:           "at_risk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := assessOnTrack(tt.tasksCompleted, tt.weeklyRate, tt.daysRemaining)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("assessOnTrack(%d, %g, %d) mismatch (-want +got):\n%s",
					tt.tasksCompleted, tt.weeklyRate, tt.daysRemaining, diff)
			}
		})
	}
}
