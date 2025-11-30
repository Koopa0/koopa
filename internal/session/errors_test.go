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
	for b.Loop() {
		for _, branch := range branches {
			_, _ = NormalizeBranch(branch)
		}
	}
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

// FuzzNormalizeBranch tests NormalizeBranch against malicious inputs.
// This is security-critical as branch names may affect SQL queries.
// Run with: go test -fuzz=FuzzNormalizeBranch -fuzztime=30s ./internal/session/
func FuzzNormalizeBranch(f *testing.F) {
	// Seed corpus with known attack vectors
	seedCorpus := []string{
		// Valid cases
		"main",
		"main.research",
		"chat.agent1.subtask",

		// Path traversal attempts
		"../../../etc/passwd",
		"..\\..\\windows\\system32",
		"main/../../../etc/passwd",

		// SQL injection attempts
		"'; DROP TABLE sessions; --",
		"main' OR '1'='1",
		"main; DELETE FROM messages;",
		"main UNION SELECT * FROM users--",

		// Null byte injection
		"main\x00evil",
		"\x00",

		// Unicode attacks
		"main\u202e\u202d",    // Right-to-left override
		"main\ufeff",          // BOM
		"ｍａｉｎ",                // Fullwidth characters
		"main\u0000.research", // Embedded null
		"main\u3002research",  // Ideographic full stop

		// Double URL encoding attacks
		"%252e%252e",             // Double-encoded ".."
		"main%252e%252e%252fetc", // Double-encoded path traversal
		"%25252e%25252e",         // Triple-encoded ".."

		// UTF-8 overlong encoding attacks
		"%c0%ae%c0%ae",       // Overlong ".." (2-byte)
		"%e0%80%ae%e0%80%ae", // Overlong ".." (3-byte)
		"main%c0%aeetc",      // Overlong "." in path

		// Length attacks
		strings.Repeat("a", 300),
		strings.Repeat("a.b.", 100),

		// Format string attacks
		"main%s%s%s%n",
		"main%x%x%x",

		// Shell injection attempts
		"main; rm -rf /",
		"main | cat /etc/passwd",
		"main $(whoami)",
		"main `id`",

		// Edge cases
		"",
		".",
		"..",
		"...",
		"main.",
		".main",
		"main..sub",
		"a.b.c.d.e.f.g.h.i.j.k", // Exceeds max depth
	}

	for _, seed := range seedCorpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result, err := NormalizeBranch(input)

		// Property 1: Valid results must not exceed MaxBranchLength
		if err == nil && len(result) > MaxBranchLength {
			t.Errorf("result exceeds max length: len=%d max=%d", len(result), MaxBranchLength)
		}

		// Property 2: Valid results must not contain dangerous characters
		if err == nil {
			dangerousChars := []string{";", "'", "\"", "--", "/*", "*/", "\x00", "|", "&", "`", "$", "(", ")"}
			for _, char := range dangerousChars {
				if strings.Contains(result, char) {
					t.Errorf("result contains dangerous char: result=%q char=%q", result, char)
				}
			}
		}

		// Property 3: Valid results must match expected pattern (letters, numbers, underscores, dots)
		if err == nil {
			for i, c := range result {
				isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
				isDigit := c >= '0' && c <= '9'
				isUnderscore := c == '_'
				isDot := c == '.'

				if !isLetter && !isDigit && !isUnderscore && !isDot {
					t.Errorf("result contains invalid char at position %d: result=%q char=%q", i, result, string(c))
				}
			}
		}

		// Property 4: Empty input must return DefaultBranch
		if input == "" && err == nil && result != DefaultBranch {
			t.Errorf("empty input should return default branch: got=%q want=%q", result, DefaultBranch)
		}

		// Property 5: Path traversal must ALWAYS be rejected (input check)
		if strings.Contains(input, "..") {
			if err == nil {
				t.Errorf("input with '..' should be rejected: input=%q result=%q", input, result)
			}
		}

		// Property 5b: Result must NEVER contain path traversal (output check)
		// Defense in depth - even if input doesn't contain "..", result shouldn't either
		if err == nil && strings.Contains(result, "..") {
			t.Errorf("result contains '..': input=%q result=%q", input, result)
		}

		// Property 5c: Encoded bypass detection (URL encoding attacks)
		// Check for %2e%2e (URL-encoded "..")
		if err == nil {
			decoded := strings.ReplaceAll(result, "%2e", ".")
			decoded = strings.ReplaceAll(decoded, "%2E", ".")
			if strings.Contains(decoded, "..") {
				t.Errorf("result contains encoded '..': input=%q result=%q decoded=%q",
					input, result, decoded)
			}
		}

		// Property 5d: Double URL encoding bypass detection
		// Check for %252e%252e (double-encoded ".." -> %2e%2e -> ..)
		if err == nil {
			// First pass: decode %25 -> %
			decoded := strings.ReplaceAll(result, "%252e", "%2e")
			decoded = strings.ReplaceAll(decoded, "%252E", "%2E")
			// Second pass: decode %2e -> .
			decoded = strings.ReplaceAll(decoded, "%2e", ".")
			decoded = strings.ReplaceAll(decoded, "%2E", ".")
			if strings.Contains(decoded, "..") {
				t.Errorf("result contains double-encoded '..': input=%q result=%q decoded=%q",
					input, result, decoded)
			}
		}

		// Property 5e: UTF-8 overlong encoding bypass detection
		// Overlong encodings like %C0%AE could be decoded as "." by some parsers
		// These are invalid UTF-8 sequences that should never appear in valid output
		if err == nil {
			// Check for common overlong dot encodings
			overlongPatterns := []string{
				"%c0%ae", "%C0%AE", // 2-byte overlong "."
				"%e0%80%ae", "%E0%80%AE", // 3-byte overlong "."
				"%c0%2e", "%C0%2E", // Mixed overlong
			}
			for _, pattern := range overlongPatterns {
				if strings.Contains(strings.ToLower(result), strings.ToLower(pattern)) {
					t.Errorf("result contains overlong UTF-8 encoding: input=%q result=%q pattern=%q",
						input, result, pattern)
				}
			}
		}

		// Property 6: Null bytes must cause rejection
		if strings.Contains(input, "\x00") {
			if err == nil {
				t.Errorf("null byte should cause rejection: input=%q", input)
			}
		}
	})
}
