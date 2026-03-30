package retrieval

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestSM2Calculate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name         string
		prevInterval int
		prevEase     float64
		quality      string
		wantInterval int
		wantEase     float64
		wantNextDue  string
	}{
		{
			name:         "first attempt easy",
			prevInterval: 0, prevEase: 2.5,
			quality:      QualityEasy,
			wantInterval: 3, wantEase: 2.5,
			wantNextDue: "2026-03-28",
		},
		{
			name:         "first attempt hard",
			prevInterval: 0, prevEase: 2.5,
			quality:      QualityHard,
			wantInterval: 1, wantEase: 2.5,
			wantNextDue: "2026-03-26",
		},
		{
			name:         "first attempt failed",
			prevInterval: 0, prevEase: 2.5,
			quality:      QualityFailed,
			wantInterval: 1, wantEase: 2.5,
			wantNextDue: "2026-03-26",
		},
		{
			name:         "second attempt easy after 3 days",
			prevInterval: 3, prevEase: 2.5,
			quality:      QualityEasy,
			wantInterval: 8, wantEase: 2.65,
			wantNextDue: "2026-04-02",
		},
		{
			name:         "second attempt hard after 1 day",
			prevInterval: 1, prevEase: 2.5,
			quality:      QualityHard,
			wantInterval: 2, wantEase: 2.35,
			wantNextDue: "2026-03-27",
		},
		{
			name:         "hard always grows at least 1",
			prevInterval: 1, prevEase: 1.3,
			quality:      QualityHard,
			wantInterval: 2, wantEase: 1.3, // already at floor
			wantNextDue: "2026-03-27",
		},
		{
			name:         "failed resets to 1",
			prevInterval: 14, prevEase: 2.5,
			quality:      QualityFailed,
			wantInterval: 1, wantEase: 2.3,
			wantNextDue: "2026-03-26",
		},
		{
			name:         "ease floor at 1.3",
			prevInterval: 3, prevEase: 1.35,
			quality:      QualityFailed,
			wantInterval: 1, wantEase: 1.3,
			wantNextDue: "2026-03-26",
		},
		{
			name:         "easy grows interval with multiplier",
			prevInterval: 7, prevEase: 2.5,
			quality:      QualityEasy,
			wantInterval: 18, wantEase: 2.65,
			wantNextDue: "2026-04-12",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := SM2Calculate(tt.prevInterval, tt.prevEase, tt.quality, now)
			want := SM2Result{
				IntervalDays: tt.wantInterval,
				EaseFactor:   tt.wantEase,
				NextDue:      tt.wantNextDue,
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("SM2Calculate(%d, %.2f, %q) mismatch (-want +got):\n%s",
					tt.prevInterval, tt.prevEase, tt.quality, diff)
			}
		})
	}
}

func TestValidQuality(t *testing.T) {
	t.Parallel()

	tests := []struct {
		quality string
		want    bool
	}{
		{"easy", true},
		{"hard", true},
		{"failed", true},
		{"", false},
		{"medium", false},
		{"Easy", false},
	}

	for _, tt := range tests {
		t.Run(tt.quality, func(t *testing.T) {
			t.Parallel()
			if got := ValidQuality(tt.quality); got != tt.want {
				t.Errorf("ValidQuality(%q) = %v, want %v", tt.quality, got, tt.want)
			}
		})
	}
}
