package learning

import (
	"errors"
	"testing"
)

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
		mode         Mode
		input        string
		wantParadigm Paradigm
		wantOutcome  string
		wantErr      bool
	}{
		// Practice mode — problem-solving paradigm.
		{ModePractice, "got it", ParadigmProblemSolving, "solved_independent", false},
		{ModePractice, "solved it", ParadigmProblemSolving, "solved_independent", false},
		{ModePractice, "nailed it", ParadigmProblemSolving, "solved_independent", false},
		{ModePractice, "needed help", ParadigmProblemSolving, "solved_with_hint", false},
		{ModePractice, "needed a hint", ParadigmProblemSolving, "solved_with_hint", false},
		{ModePractice, "got help", ParadigmProblemSolving, "solved_with_hint", false},
		{ModePractice, "saw answer", ParadigmProblemSolving, "solved_after_solution", false},
		{ModePractice, "saw the answer first", ParadigmProblemSolving, "solved_after_solution", false},
		{ModePractice, "didn't finish", ParadigmProblemSolving, "incomplete", false},
		{ModePractice, "gave up", ParadigmProblemSolving, "gave_up", false},
		{ModePractice, "stuck", ParadigmProblemSolving, "gave_up", false},

		// Retrieval mode — same as practice.
		{ModeRetrieval, "got it", ParadigmProblemSolving, "solved_independent", false},
		{ModeRetrieval, "needed help", ParadigmProblemSolving, "solved_with_hint", false},

		// Mixed mode — same as practice.
		{ModeMixed, "got it", ParadigmProblemSolving, "solved_independent", false},
		{ModeMixed, "gave up", ParadigmProblemSolving, "gave_up", false},

		// Review mode — same as practice.
		{ModeReview, "got it", ParadigmProblemSolving, "solved_independent", false},

		// Reading mode — immersive paradigm.
		{ModeReading, "got it", ParadigmImmersive, "completed", false},
		{ModeReading, "finished", ParadigmImmersive, "completed", false},
		{ModeReading, "done", ParadigmImmersive, "completed", false},
		{ModeReading, "needed help", ParadigmImmersive, "completed_with_support", false},
		{ModeReading, "needed support", ParadigmImmersive, "completed_with_support", false},
		{ModeReading, "didn't finish", ParadigmImmersive, "incomplete", false},
		{ModeReading, "gave up", ParadigmImmersive, "gave_up", false},

		// Raw enum values — paradigm is implied by outcome for paradigm-specific
		// values; mode only disambiguates shared outcomes (incomplete / gave_up).
		{ModePractice, "solved_independent", ParadigmProblemSolving, "solved_independent", false},
		{ModePractice, "solved_with_hint", ParadigmProblemSolving, "solved_with_hint", false},
		{ModePractice, "solved_after_solution", ParadigmProblemSolving, "solved_after_solution", false},
		{ModePractice, "completed", ParadigmImmersive, "completed", false},
		{ModePractice, "completed_with_support", ParadigmImmersive, "completed_with_support", false},
		{ModePractice, "incomplete", ParadigmProblemSolving, "incomplete", false},
		{ModePractice, "gave_up", ParadigmProblemSolving, "gave_up", false},
		{ModeReading, "incomplete", ParadigmImmersive, "incomplete", false},
		{ModeReading, "gave_up", ParadigmImmersive, "gave_up", false},
		{ModeReading, "solved_independent", ParadigmProblemSolving, "solved_independent", false},

		// Unrecognized semantic input → error.
		{ModePractice, "unknown input", "", "", true},
		{ModeReading, "unknown input", "", "", true},
		{ModePractice, "", "", "", true},
	}

	for _, tt := range tests {
		name := string(tt.mode) + "/" + tt.input
		t.Run(name, func(t *testing.T) {
			gotParadigm, gotOutcome, err := MapOutcome(tt.mode, tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("MapOutcome(%q, %q) error = %v, wantErr = %v", tt.mode, tt.input, err, tt.wantErr)
				return
			}
			if gotOutcome != tt.wantOutcome {
				t.Errorf("MapOutcome(%q, %q) outcome = %q, want %q", tt.mode, tt.input, gotOutcome, tt.wantOutcome)
			}
			if gotParadigm != tt.wantParadigm {
				t.Errorf("MapOutcome(%q, %q) paradigm = %q, want %q", tt.mode, tt.input, gotParadigm, tt.wantParadigm)
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
