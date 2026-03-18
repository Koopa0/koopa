package notion

import "testing"

func TestValidSyncMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		{"full", true},
		{"events", true},
		{"", false},
		{"snapshot", false},
		{"FULL", false},
		{"disabled", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			if got := ValidSyncMode(tt.input); got != tt.want {
				t.Errorf("ValidSyncMode(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidPollInterval(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		{"5 minutes", true},
		{"10 minutes", true},
		{"15 minutes", true},
		{"30 minutes", true},
		{"1 hour", true},
		{"2 hours", true},
		{"4 hours", true},
		{"6 hours", true},
		{"12 hours", true},
		{"24 hours", true},
		{"", false},
		{"1 minute", false},
		{"3 hours", false},
		{"48 hours", false},
		{"999 years", false},
		{"1 decade", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			if got := ValidPollInterval(tt.input); got != tt.want {
				t.Errorf("ValidPollInterval(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
