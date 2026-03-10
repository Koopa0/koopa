package feed

import "testing"

func TestValidSchedule(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "hourly_4", input: "hourly_4", want: true},
		{name: "daily", input: "daily", want: true},
		{name: "weekly", input: "weekly", want: true},
		{name: "invalid", input: "monthly", want: false},
		{name: "empty", input: "", want: false},
		{name: "case sensitive", input: "Daily", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidSchedule(tt.input)
			if got != tt.want {
				t.Errorf("ValidSchedule(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
