package learning

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

func TestValidRelationType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   RelationType
		want bool
	}{
		{in: RelationEasierVariant, want: true},
		{in: RelationHarderVariant, want: true},
		{in: RelationPrerequisite, want: true},
		{in: RelationFollowUp, want: true},
		{in: RelationSamePattern, want: true},
		{in: RelationSimilarStructure, want: true},
		{in: "nonsense", want: false},
		{in: "", want: false},
		{in: "EASIER_VARIANT", want: false}, // case-sensitive
	}
	for _, tt := range tests {
		t.Run(string(tt.in), func(t *testing.T) {
			t.Parallel()
			if got := ValidRelationType(tt.in); got != tt.want {
				t.Errorf("ValidRelationType(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestMapOutcome(t *testing.T) {
	tests := []struct {
		mode    Mode
		input   string
		want    string
		wantErr bool
	}{
		// Practice mode — problem-solving paradigm.
		{ModePractice, "got it", "solved_independent", false},
		{ModePractice, "solved it", "solved_independent", false},
		{ModePractice, "nailed it", "solved_independent", false},
		{ModePractice, "needed help", "solved_with_hint", false},
		{ModePractice, "needed a hint", "solved_with_hint", false},
		{ModePractice, "got help", "solved_with_hint", false},
		{ModePractice, "saw answer", "solved_after_solution", false},
		{ModePractice, "saw the answer first", "solved_after_solution", false},
		{ModePractice, "didn't finish", "incomplete", false},
		{ModePractice, "gave up", "gave_up", false},
		{ModePractice, "stuck", "gave_up", false},

		// Retrieval mode — same as practice.
		{ModeRetrieval, "got it", "solved_independent", false},
		{ModeRetrieval, "needed help", "solved_with_hint", false},

		// Mixed mode — same as practice.
		{ModeMixed, "got it", "solved_independent", false},
		{ModeMixed, "gave up", "gave_up", false},

		// Review mode — same as practice.
		{ModeReview, "got it", "solved_independent", false},

		// Reading mode — immersive paradigm.
		{ModeReading, "got it", "completed", false},
		{ModeReading, "finished", "completed", false},
		{ModeReading, "done", "completed", false},
		{ModeReading, "needed help", "completed_with_support", false},
		{ModeReading, "needed support", "completed_with_support", false},
		{ModeReading, "didn't finish", "incomplete", false},
		{ModeReading, "gave up", "gave_up", false},

		// Raw enum values pass through regardless of mode.
		{ModePractice, "solved_independent", "solved_independent", false},
		{ModePractice, "solved_with_hint", "solved_with_hint", false},
		{ModePractice, "solved_after_solution", "solved_after_solution", false},
		{ModePractice, "completed", "completed", false},
		{ModePractice, "completed_with_support", "completed_with_support", false},
		{ModePractice, "incomplete", "incomplete", false},
		{ModePractice, "gave_up", "gave_up", false},
		{ModeReading, "solved_independent", "solved_independent", false},

		// Unrecognized semantic input → error.
		{ModePractice, "unknown input", "", true},
		{ModeReading, "unknown input", "", true},
		{ModePractice, "", "", true},
	}

	for _, tt := range tests {
		name := string(tt.mode) + "/" + tt.input
		t.Run(name, func(t *testing.T) {
			got, err := MapOutcome(tt.mode, tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("MapOutcome(%q, %q) error = %v, wantErr = %v", tt.mode, tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("MapOutcome(%q, %q) = %q, want %q", tt.mode, tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeSignal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "weakness", in: "weakness", want: "weakness"},
		{name: "improvement", in: "improvement", want: "improvement"},
		{name: "mastery", in: "mastery", want: "mastery"},
		{name: "empty rejected", in: "", wantErr: true},
		{name: "capitalized rejected", in: "Mastery", wantErr: true},
		{name: "typo rejected", in: "weekness", wantErr: true},
		{name: "unknown rejected", in: "progress", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeSignal(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeSignal(%q) error = %v, wantErr = %v", tt.in, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidInput) {
				t.Errorf("normalizeSignal(%q) error should wrap ErrInvalidInput, got %v", tt.in, err)
			}
			if err == nil && got != tt.want {
				t.Errorf("normalizeSignal(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidateSeverity(t *testing.T) {
	t.Parallel()

	minor := "minor"
	moderate := "moderate"
	critical := "critical"
	invalid := "severe"

	tests := []struct {
		name     string
		signal   string
		severity *string
		wantErr  bool
	}{
		{name: "nil severity always valid", signal: "mastery", severity: nil},
		{name: "nil severity on weakness", signal: "weakness", severity: nil},
		{name: "minor on weakness", signal: "weakness", severity: &minor},
		{name: "moderate on weakness", signal: "weakness", severity: &moderate},
		{name: "critical on weakness", signal: "weakness", severity: &critical},
		{name: "minor on mastery rejected", signal: "mastery", severity: &minor, wantErr: true},
		{name: "minor on improvement rejected", signal: "improvement", severity: &minor, wantErr: true},
		{name: "invalid severity value", signal: "weakness", severity: &invalid, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateSeverity(tt.signal, tt.severity)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateSeverity(%q, %v) error = %v, wantErr = %v", tt.signal, tt.severity, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidInput) {
				t.Errorf("validateSeverity(%q, %v) error should wrap ErrInvalidInput, got %v", tt.signal, tt.severity, err)
			}
		})
	}
}
