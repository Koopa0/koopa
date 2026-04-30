package fsrs

import (
	"errors"
	"testing"
	"time"

	gofsrs "github.com/open-spaced-repetition/go-fsrs/v4"
)

// TestSchedulerLongTermFirstReview is the regression guard for the FSRS
// short-term scheduler decision (see fsrs.go newScheduler doc). With
// EnableShortTerm=true (gofsrs default) a new card rated Good is scheduled
// roughly 10 minutes out — the Anki "Learning state" behaviour. We want it
// to land days out instead, because LeetCode practice has no useful
// 10-minute re-test loop.
//
// If a future change reverts EnableShortTerm or moves the scheduler to a
// short-term-friendly preset, this test fails loudly instead of letting the
// retrieval queue fill up with same-day cards again.
func TestSchedulerLongTermFirstReview(t *testing.T) {
	t.Parallel()

	s := newScheduler()
	now := time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC)
	card := s.newCard()

	updated, _ := s.review(&card, gofsrs.Good, now)

	gap := updated.Due.Sub(now)
	if gap < 24*time.Hour {
		t.Fatalf("new card + Good: due gap = %s, want >= 24h "+
			"(short-term scheduler likely re-enabled — see fsrs.go)", gap)
	}

	// Easy should be even further out.
	easyCard := s.newCard()
	easyUpdated, _ := s.review(&easyCard, gofsrs.Easy, now)
	easyGap := easyUpdated.Due.Sub(now)
	if easyGap < gap {
		t.Errorf("Easy gap (%s) shorter than Good gap (%s) — rating order broken", easyGap, gap)
	}
}

// TestRatingFromOutcome covers every outcome in the closed set plus the
// drift safety net: an outcome value that is not in the switch must return
// ErrUnknownOutcome so the caller can stamp review_cards.last_sync_drift_at
// and surface drift_suspect to the retrieval view. Regression guard for the
// "silent Again fallback" smell — if a future change reverts the default
// branch to `return gofsrs.Again`, this test fails loudly.
func TestRatingFromOutcome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		outcome string
		want    gofsrs.Rating
		wantErr bool
	}{
		{name: "solved_independent → Good", outcome: "solved_independent", want: gofsrs.Good},
		{name: "completed → Good", outcome: "completed", want: gofsrs.Good},
		{name: "solved_with_hint → Hard", outcome: "solved_with_hint", want: gofsrs.Hard},
		{name: "solved_after_solution → Hard", outcome: "solved_after_solution", want: gofsrs.Hard},
		{name: "completed_with_support → Hard", outcome: "completed_with_support", want: gofsrs.Hard},
		{name: "incomplete → Again", outcome: "incomplete", want: gofsrs.Again},
		{name: "gave_up → Again", outcome: "gave_up", want: gofsrs.Again},
		{name: "unknown outcome → ErrUnknownOutcome", outcome: "bogus_outcome", wantErr: true},
		{name: "empty outcome → ErrUnknownOutcome", outcome: "", wantErr: true},
		{name: "typo of known outcome → ErrUnknownOutcome", outcome: "solved-independent", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ratingFromOutcome(tt.outcome)
			if tt.wantErr {
				if !errors.Is(err, ErrUnknownOutcome) {
					t.Errorf("ratingFromOutcome(%q) error = %v, want ErrUnknownOutcome", tt.outcome, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ratingFromOutcome(%q) error = %v, want nil", tt.outcome, err)
			}
			if got != tt.want {
				t.Errorf("ratingFromOutcome(%q) = %v, want %v", tt.outcome, got, tt.want)
			}
		})
	}
}

// TestPublicRatingFromOutcome verifies the exported RatingFromOutcome
// returns the int form of the same mapping, suitable for echoing in MCP
// responses. Coverage mirrors TestRatingFromOutcome so a future change
// to one mapping cannot land without updating both.
func TestPublicRatingFromOutcome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		outcome string
		want    int
		wantErr bool
	}{
		{name: "solved_independent → 3 (Good)", outcome: "solved_independent", want: 3},
		{name: "completed → 3 (Good)", outcome: "completed", want: 3},
		{name: "solved_with_hint → 2 (Hard)", outcome: "solved_with_hint", want: 2},
		{name: "solved_after_solution → 2 (Hard)", outcome: "solved_after_solution", want: 2},
		{name: "completed_with_support → 2 (Hard)", outcome: "completed_with_support", want: 2},
		{name: "incomplete → 1 (Again)", outcome: "incomplete", want: 1},
		{name: "gave_up → 1 (Again)", outcome: "gave_up", want: 1},
		{name: "unknown outcome → ErrUnknownOutcome", outcome: "bogus_outcome", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := RatingFromOutcome(tt.outcome)
			if tt.wantErr {
				if !errors.Is(err, ErrUnknownOutcome) {
					t.Errorf("RatingFromOutcome(%q) error = %v, want ErrUnknownOutcome", tt.outcome, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("RatingFromOutcome(%q) error = %v, want nil", tt.outcome, err)
			}
			if got != tt.want {
				t.Errorf("RatingFromOutcome(%q) = %d, want %d", tt.outcome, got, tt.want)
			}
		})
	}
}

func TestFSRSRatingFromInt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      int
		want    gofsrs.Rating
		wantErr bool
	}{
		{name: "again", in: 1, want: gofsrs.Again},
		{name: "hard", in: 2, want: gofsrs.Hard},
		{name: "good", in: 3, want: gofsrs.Good},
		{name: "easy", in: 4, want: gofsrs.Easy},
		{name: "zero rejected", in: 0, wantErr: true},
		{name: "negative rejected", in: -1, wantErr: true},
		{name: "above range rejected", in: 5, wantErr: true},
		{name: "large rejected", in: 999, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := fsrsRatingFromInt(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("fsrsRatingFromInt(%d) error = %v, wantErr = %v", tt.in, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("fsrsRatingFromInt(%d) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
