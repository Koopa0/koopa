package session

import "testing"

// TestNormalizeRole tests the Genkit role normalization function.
// Genkit uses "model" for AI responses, but we store "assistant" in the database
// for consistency with the CHECK constraint.
func TestNormalizeRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "model to assistant", input: "model", want: "assistant"},
		{name: "user unchanged", input: "user", want: "user"},
		{name: "assistant unchanged", input: "assistant", want: "assistant"},
		{name: "system unchanged", input: "system", want: "system"},
		{name: "tool unchanged", input: "tool", want: "tool"},
		{name: "empty passthrough", input: "", want: ""},
		{name: "unknown passthrough", input: "unknown", want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeRole(tt.input)
			if got != tt.want {
				t.Errorf("normalizeRole(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
