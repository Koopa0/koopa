package learning

import "testing"

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
