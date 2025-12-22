package session

import (
	"testing"
)

func TestNormalizeHistoryLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input int32
		want  int32
	}{
		// Default cases
		{"zero defaults", 0, DefaultHistoryLimit},
		{"negative defaults", -1, DefaultHistoryLimit},
		{"large negative defaults", -999, DefaultHistoryLimit},

		// Clamping to minimum
		{"below min clamped", MinHistoryLimit - 1, MinHistoryLimit},
		{"exactly min", MinHistoryLimit, MinHistoryLimit},

		// Valid middle values
		{"valid 50", 50, 50},
		{"valid 100", 100, 100},
		{"valid 500", 500, 500},
		{"valid 5000", 5000, 5000},

		// Clamping to maximum
		{"exactly max", MaxHistoryLimit, MaxHistoryLimit},
		{"above max clamped", MaxHistoryLimit + 1, MaxHistoryLimit},
		{"large above max", MaxHistoryLimit * 2, MaxHistoryLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeHistoryLimit(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeHistoryLimit(%d) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	t.Parallel()

	t.Run("DefaultHistoryLimit", func(t *testing.T) {
		if DefaultHistoryLimit != 100 {
			t.Errorf("DefaultHistoryLimit = %d, want %d", DefaultHistoryLimit, 100)
		}
	})

	t.Run("MaxHistoryLimit", func(t *testing.T) {
		if MaxHistoryLimit != 10000 {
			t.Errorf("MaxHistoryLimit = %d, want %d", MaxHistoryLimit, 10000)
		}
	})

	t.Run("MinHistoryLimit", func(t *testing.T) {
		if MinHistoryLimit != 10 {
			t.Errorf("MinHistoryLimit = %d, want %d", MinHistoryLimit, 10)
		}
	})

	t.Run("StatusConstants", func(t *testing.T) {
		if StatusStreaming != "streaming" {
			t.Errorf("StatusStreaming = %q, want %q", StatusStreaming, "streaming")
		}
		if StatusCompleted != "completed" {
			t.Errorf("StatusCompleted = %q, want %q", StatusCompleted, "completed")
		}
		if StatusFailed != "failed" {
			t.Errorf("StatusFailed = %q, want %q", StatusFailed, "failed")
		}
	})
}

// BenchmarkNormalizeHistoryLimit benchmarks limit normalization.
func BenchmarkNormalizeHistoryLimit(b *testing.B) {
	limits := []int32{0, -1, 50, 100, 10001}

	b.ResetTimer()
	for b.Loop() {
		for _, limit := range limits {
			_ = NormalizeHistoryLimit(limit)
		}
	}
}

// TestNormalizeRole tests the Genkit role normalization function.
// Genkit uses "model" for AI responses, but we store "assistant" in the database
// for consistency with the CHECK constraint.
func TestNormalizeRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"model to assistant", "model", "assistant"},
		{"user unchanged", "user", "user"},
		{"assistant unchanged", "assistant", "assistant"},
		{"system unchanged", "system", "system"},
		{"tool unchanged", "tool", "tool"},
		{"empty passthrough", "", ""},
		{"unknown passthrough", "unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeRole(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeRole(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
