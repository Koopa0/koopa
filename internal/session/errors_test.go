package session

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeBranch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		// Default cases
		{"empty defaults to main", "", DefaultBranch, nil},

		// Valid simple names
		{"valid simple", "main", "main", nil},
		{"valid with underscore", "my_branch", "my_branch", nil},
		{"valid uppercase", "Main", "Main", nil},
		{"valid mixed case", "MyBranch", "MyBranch", nil},
		{"valid with numbers", "branch123", "branch123", nil},
		{"valid underscore middle", "my_branch_123", "my_branch_123", nil},

		// Valid hierarchical names (dot-separated)
		{"valid two segments", "main.research", "main.research", nil},
		{"valid three segments", "chat.agent1.subtask", "chat.agent1.subtask", nil},
		{"valid max depth (10)", "a.b.c.d.e.f.g.h.i.j", "a.b.c.d.e.f.g.h.i.j", nil},

		// Invalid - starts with non-letter
		{"starts with number", "123abc", "", ErrInvalidBranch},
		{"starts with underscore", "_branch", "", ErrInvalidBranch},
		{"starts with dot", ".branch", "", ErrInvalidBranch},

		// Invalid - special characters
		{"contains hyphen", "my-branch", "", ErrInvalidBranch},
		{"contains slash", "my/branch", "", ErrInvalidBranch},
		{"contains space", "my branch", "", ErrInvalidBranch},
		{"contains at sign", "my@branch", "", ErrInvalidBranch},

		// Invalid - dot issues
		{"ends with dot", "branch.", "", ErrInvalidBranch},
		{"consecutive dots", "main..sub", "", ErrInvalidBranch},
		{"only dot", ".", "", ErrInvalidBranch},

		// Invalid - segment issues
		{"segment starts with number", "main.123sub", "", ErrInvalidBranch},
		{"segment starts with underscore", "main._sub", "", ErrInvalidBranch},

		// Too deep
		{"exceeds max depth (11)", "a.b.c.d.e.f.g.h.i.j.k", "", ErrBranchTooDeep},

		// Too long
		{"exceeds max length", strings.Repeat("a", MaxBranchLength+1), "", ErrBranchTooLong},
		{"exactly max length", strings.Repeat("a", MaxBranchLength), strings.Repeat("a", MaxBranchLength), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := NormalizeBranch(tt.input)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("NormalizeBranch(%q) expected error %v, got nil", tt.input, tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("NormalizeBranch(%q) error = %v, want %v", tt.input, err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("NormalizeBranch(%q) unexpected error: %v", tt.input, err)
				return
			}

			if got != tt.want {
				t.Errorf("NormalizeBranch(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

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
			t.Parallel()

			got := NormalizeHistoryLimit(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeHistoryLimit(%d) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestSplitBranch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"empty", "", nil},
		{"single segment", "main", []string{"main"}},
		{"two segments", "main.sub", []string{"main", "sub"}},
		{"three segments", "a.b.c", []string{"a", "b", "c"}},
		{"leading dot", ".main", []string{"", "main"}},
		{"trailing dot", "main.", []string{"main", ""}},
		{"consecutive dots", "main..sub", []string{"main", "", "sub"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := splitBranch(tt.input)

			if len(got) != len(tt.want) {
				t.Errorf("splitBranch(%q) = %v, want %v", tt.input, got, tt.want)
				return
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitBranch(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIsValidSegment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Valid segments
		{"simple lowercase", "main", true},
		{"simple uppercase", "Main", true},
		{"with numbers", "branch123", true},
		{"with underscore", "my_branch", true},
		{"single letter", "a", true},
		{"mixed", "MyBranch_123", true},

		// Invalid segments
		{"empty", "", false},
		{"starts with number", "123abc", false},
		{"starts with underscore", "_branch", false},
		{"contains hyphen", "my-branch", false},
		{"contains space", "my branch", false},
		{"contains dot", "my.branch", false},
		{"contains slash", "my/branch", false},
		{"only number", "123", false},
		{"only underscore", "_", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := isValidSegment(tt.input)
			if got != tt.want {
				t.Errorf("isValidSegment(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	t.Parallel()

	// Verify constants match expected values (sync with config package)
	t.Run("DefaultBranch", func(t *testing.T) {
		if DefaultBranch != "main" {
			t.Errorf("DefaultBranch = %q, want %q", DefaultBranch, "main")
		}
	})

	t.Run("MaxBranchLength", func(t *testing.T) {
		if MaxBranchLength != 256 {
			t.Errorf("MaxBranchLength = %d, want %d", MaxBranchLength, 256)
		}
	})

	t.Run("MaxBranchDepth", func(t *testing.T) {
		if MaxBranchDepth != 10 {
			t.Errorf("MaxBranchDepth = %d, want %d", MaxBranchDepth, 10)
		}
	})

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
}

// BenchmarkNormalizeBranch benchmarks branch validation.
func BenchmarkNormalizeBranch(b *testing.B) {
	branches := []string{
		"",
		"main",
		"main.research",
		"chat.agent1.subtask.deep.branch",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, branch := range branches {
			_, _ = NormalizeBranch(branch)
		}
	}
}

// BenchmarkNormalizeHistoryLimit benchmarks limit normalization.
func BenchmarkNormalizeHistoryLimit(b *testing.B) {
	limits := []int32{0, -1, 50, 100, 10001}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, limit := range limits {
			_ = NormalizeHistoryLimit(limit)
		}
	}
}
