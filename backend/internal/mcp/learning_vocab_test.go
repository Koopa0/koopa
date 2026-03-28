package mcp

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// --- normalizeTag ---

func TestNormalizeTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "already lowercase",
			input: "array",
			want:  "array",
		},
		{
			name:  "uppercase converted",
			input: "ARRAY",
			want:  "array",
		},
		{
			name:  "mixed case converted",
			input: "BinarySearch",
			want:  "binarysearch",
		},
		{
			name:  "spaces replaced with hyphens",
			input: "two pointers",
			want:  "two-pointers",
		},
		{
			name:  "leading and trailing spaces trimmed",
			input: "  dp  ",
			want:  "dp",
		},
		{
			name:  "spaces and uppercase combined",
			input: "  Hash Table  ",
			want:  "hash-table",
		},
		{
			name:  "already has hyphens unchanged",
			input: "linked-list",
			want:  "linked-list",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "only spaces",
			input: "   ",
			want:  "",
		},
		{
			name:  "colon preserved",
			input: "weakness:pattern-recognition",
			want:  "weakness:pattern-recognition",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeTag(tt.input)
			if got != tt.want {
				t.Errorf("normalizeTag(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func FuzzNormalizeTag(f *testing.F) {
	f.Add("array")
	f.Add("Two Pointers")
	f.Add("  HEAP  ")
	f.Add("")
	f.Add("weakness:pattern-recognition")
	f.Fuzz(func(t *testing.T, input string) {
		got := normalizeTag(input)
		// Must not panic.
		// Invariant: result has no uppercase letters.
		for _, r := range got {
			if r >= 'A' && r <= 'Z' {
				t.Errorf("normalizeTag(%q) = %q contains uppercase rune %q", input, got, r)
			}
		}
		// Invariant: result has no leading or trailing spaces.
		if got != "" && (got[0] == ' ' || got[len(got)-1] == ' ') {
			t.Errorf("normalizeTag(%q) = %q has leading/trailing space", input, got)
		}
	})
}

// --- validateLearningInput ---

func TestValidateLearningInput(t *testing.T) {
	t.Parallel()

	validBase := func() *LogLearningSessionInput {
		return &LogLearningSessionInput{
			Project: "none",
			Topic:   "two pointers",
			Title:   "My Session",
			Body:    "learned something",
		}
	}

	tests := []struct {
		name    string
		input   *LogLearningSessionInput
		wantErr bool
	}{
		{
			name:  "valid minimal input",
			input: validBase(),
		},
		{
			name: "missing project",
			input: func() *LogLearningSessionInput {
				i := validBase()
				i.Project = ""
				return i
			}(),
			wantErr: true,
		},
		{
			name: "missing topic",
			input: func() *LogLearningSessionInput {
				i := validBase()
				i.Topic = ""
				return i
			}(),
			wantErr: true,
		},
		{
			name: "missing title",
			input: func() *LogLearningSessionInput {
				i := validBase()
				i.Title = ""
				return i
			}(),
			wantErr: true,
		},
		{
			name: "missing body",
			input: func() *LogLearningSessionInput {
				i := validBase()
				i.Body = ""
				return i
			}(),
			wantErr: true,
		},
		{
			name: "valid difficulty easy",
			input: func() *LogLearningSessionInput {
				i := validBase()
				i.Difficulty = "easy"
				return i
			}(),
		},
		{
			name: "difficulty normalised from uppercase",
			input: func() *LogLearningSessionInput {
				i := validBase()
				i.Difficulty = "MEDIUM"
				return i
			}(),
		},
		{
			name: "invalid difficulty rejected",
			input: func() *LogLearningSessionInput {
				i := validBase()
				i.Difficulty = "novice"
				return i
			}(),
			wantErr: true,
		},
		{
			name: "empty source defaults to discussion",
			input: func() *LogLearningSessionInput {
				i := validBase()
				i.Source = ""
				return i
			}(),
		},
		{
			name: "strict mode project with valid tags",
			input: func() *LogLearningSessionInput {
				i := validBase()
				i.Project = "leetcode"
				i.Source = "leetcode"
				i.Tags = []string{"dp", "medium", "ac-independent"}
				return i
			}(),
		},
		{
			name: "strict mode project with invalid tag",
			input: func() *LogLearningSessionInput {
				i := validBase()
				i.Project = "leetcode"
				i.Source = "leetcode"
				i.Tags = []string{"unknown-tag"}
				return i
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := validateLearningInput(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("validateLearningInput() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("validateLearningInput() unexpected error: %v", err)
			}
		})
	}
}

// --- validateLearningTags ---

func TestValidateLearningTags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		tags    []string
		project string
		want    []string
		wantErr bool
	}{
		{
			name:    "empty tags returns empty",
			tags:    []string{},
			project: "blog",
			want:    []string{},
		},
		{
			name:    "nil tags returns nil",
			tags:    nil,
			project: "blog",
			want:    nil,
		},
		{
			name:    "non-strict project normalises tags",
			tags:    []string{"GO", "Algorithms"},
			project: "blog",
			want:    []string{"go", "algorithms"},
		},
		{
			name:    "strict project accepts canonical tags",
			tags:    []string{"dp", "medium", "leetcode"},
			project: "leetcode",
			want:    []string{"dp", "medium", "leetcode"},
		},
		{
			name:    "strict project normalises before validation",
			tags:    []string{"DP", "MEDIUM"},
			project: "leetcode",
			want:    []string{"dp", "medium"},
		},
		{
			name:    "strict project rejects unknown tag",
			tags:    []string{"dp", "custom-tag"},
			project: "leetcode",
			wantErr: true,
		},
		{
			name:    "hackerrank is also strict",
			tags:    []string{"dp", "custom-tag"},
			project: "hackerrank",
			wantErr: true,
		},
		{
			name:    "strict project uppercase name treated as strict",
			tags:    []string{"dp"},
			project: "LEETCODE",
			want:    []string{"dp"},
		},
		{
			name:    "weakness tag accepted in strict mode",
			tags:    []string{"weakness:pattern-recognition"},
			project: "leetcode",
			want:    []string{"weakness:pattern-recognition"},
		},
		{
			name:    "improvement tag accepted in strict mode",
			tags:    []string{"improvement:edge-cases"},
			project: "leetcode",
			want:    []string{"improvement:edge-cases"},
		},
		{
			name:    "result tag ac-independent accepted",
			tags:    []string{"ac-independent"},
			project: "leetcode",
			want:    []string{"ac-independent"},
		},
		{
			name:    "multiple invalid tags reported together",
			tags:    []string{"foo", "bar"},
			project: "leetcode",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := validateLearningTags(tt.tags, tt.project)
			if tt.wantErr {
				if err == nil {
					t.Fatal("validateLearningTags() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("validateLearningTags() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("validateLearningTags(%v, %q) mismatch (-want +got):\n%s", tt.tags, tt.project, diff)
			}
		})
	}
}
