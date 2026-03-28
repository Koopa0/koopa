package mcpserver

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// --- extractFirstSentence ---

func TestExtractFirstSentence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple sentence ending with period",
			input: "Hello world. Second sentence.",
			want:  "Hello world.",
		},
		{
			name:  "exclamation mark",
			input: "Great news! More follows.",
			want:  "Great news!",
		},
		{
			name:  "question mark",
			input: "Is this right? Yes it is.",
			want:  "Is this right?",
		},
		{
			name:  "no punctuation within 100 runes returns body",
			input: "No sentence ending here",
			want:  "No sentence ending here",
		},
		{
			name:  "no punctuation over 100 runes truncates with ellipsis",
			input: strings.Repeat("a", 101),
			want:  strings.Repeat("a", 100) + "...",
		},
		{
			name:  "markdown bold stripped via heading skip, then sentence extracted",
			input: "# Heading\nActual sentence. Second.",
			want:  "Actual sentence.",
		},
		{
			name:  "multiple headings stripped",
			input: "# H1\n## H2\nContent sentence. More.",
			want:  "Content sentence.",
		},
		{
			name:  "CJK period (。)",
			input: "你好世界。第二句。",
			want:  "你好世界。",
		},
		{
			name:  "CJK exclamation (！)",
			input: "很好！继续。",
			want:  "很好！",
		},
		{
			name:  "CJK question (？)",
			input: "是吗？对的。",
			want:  "是吗？",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "only whitespace",
			input: "   ",
			want:  "",
		},
		{
			name:  "only a markdown heading with no body",
			input: "# Just a heading",
			want:  "# Just a heading",
		},
		{
			name:  "paragraph break stops extraction",
			input: "First paragraph\nSecond paragraph.",
			want:  "First paragraph",
		},
		{
			name:  "multiple sentences — returns only first",
			input: "First. Second. Third.",
			want:  "First.",
		},
		{
			name:  "exactly 100 runes, no punctuation, returns body unchanged",
			input: strings.Repeat("b", 100),
			want:  strings.Repeat("b", 100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractFirstSentence(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("extractFirstSentence(%q) mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}

// --- truncateToCharLimit ---

func TestTruncateToCharLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		limit int
		want  string
	}{
		{
			name:  "body within limit returned unchanged",
			input: "short text",
			limit: 100,
			want:  "short text",
		},
		{
			name:  "body over limit truncates at word boundary",
			input: "one two three four five",
			limit: 11,
			// runes[:11] = "one two thr"; last space before >5 (limit/2) is at index 7
			want: "one two...",
		},
		{
			name:  "single long word with no spaces truncates at limit",
			input: "superlongword",
			limit: 5,
			// no space after limit/2 (2), truncated = "super", no space found
			want: "super...",
		},
		{
			name:  "empty string",
			input: "",
			limit: 10,
			want:  "",
		},
		{
			name:  "CJK rune counting — 5 CJK chars under limit",
			input: "你好世界啊",
			limit: 10,
			want:  "你好世界啊",
		},
		{
			name:  "CJK rune counting — truncates at rune boundary",
			input: "你好世界啊再见朋友们",
			limit: 5,
			// 5 runes = "你好世界啊", no ASCII space so last space search finds nothing beyond limit/2
			want: "你好世界啊...",
		},
		{
			name:  "exact limit returns unchanged",
			input: "abcde",
			limit: 5,
			want:  "abcde",
		},
		{
			name:  "limit of zero truncates everything",
			input: "hello world",
			limit: 0,
			// runes[:0] = ""; lastSpace returns -1, not > 0 (limit/2 = 0)
			want: "...",
		},
		{
			name:  "markdown heading stripped before truncation",
			input: "# Title\nThis is the actual body content that is long enough to be truncated at some point here.",
			limit: 20,
			want:  "This is the actual...",
		},
		{
			name:  "body at limit plus 1 truncates",
			input: "hello world!",
			limit: 11,
			// runes[:11] = "hello world"; last space at index 5 > 5 (limit/2=5), NOT strictly greater
			// lastSpace(5) > 5 is false, so no word-break; result = "hello world..."
			want: "hello world...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := truncateToCharLimit(tt.input, tt.limit)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("truncateToCharLimit(%q, %d) mismatch (-want +got):\n%s", tt.input, tt.limit, diff)
			}
		})
	}
}

// --- tagsToHashtags ---

func TestTagsToHashtags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "empty slice returns empty slice (not nil)",
			input: []string{},
			want:  []string{},
		},
		{
			name:  "nil slice returns empty slice",
			input: nil,
			want:  []string{},
		},
		{
			name:  "single tag",
			input: []string{"golang"},
			want:  []string{"#golang"},
		},
		{
			name:  "multiple tags",
			input: []string{"go", "backend", "api"},
			want:  []string{"#go", "#backend", "#api"},
		},
		{
			name:  "tags with spaces — spaces removed",
			input: []string{"machine learning", "deep learning"},
			want:  []string{"#machinelearning", "#deeplearning"},
		},
		{
			name:  "tags with hyphens — hyphens removed",
			input: []string{"go-lang", "open-source"},
			want:  []string{"#golang", "#opensource"},
		},
		{
			name:  "tags with both spaces and hyphens — both removed",
			input: []string{"open source - go"},
			want:  []string{"#opensourcego"},
		},
		{
			name:  "tag already starts with hash — gets double hash",
			input: []string{"#alreadyHashtag"},
			want:  []string{"##alreadyHashtag"},
		},
		{
			name:  "tag with special chars other than space/hyphen — kept as-is",
			input: []string{"go/lang"},
			want:  []string{"#go/lang"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tagsToHashtags(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("tagsToHashtags(%v) mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}

// --- Benchmarks ---

func BenchmarkExtractFirstSentence(b *testing.B) {
	input := "This is a fairly representative blog post opening sentence with some length. " +
		"And here is the second sentence which should never be reached."
	for b.Loop() {
		extractFirstSentence(input)
	}
}

func BenchmarkTruncateToCharLimit(b *testing.B) {
	input := strings.Repeat("This is a word. ", 50) // 800 chars, well over any limit
	for b.Loop() {
		truncateToCharLimit(input, linkedinCharLimit)
	}
}

// --- Fuzz tests ---

// FuzzExtractFirstSentence verifies extractFirstSentence never panics on arbitrary input.
func FuzzExtractFirstSentence(f *testing.F) {
	f.Add("Hello world.")
	f.Add("")
	f.Add("# Heading\nSentence.")
	f.Add("你好世界。")
	f.Add(strings.Repeat("x", 200))
	f.Add("no punctuation here")
	f.Fuzz(func(t *testing.T, input string) {
		_ = extractFirstSentence(input) // must not panic
	})
}

// FuzzTruncateToCharLimit verifies truncateToCharLimit never panics on arbitrary input.
func FuzzTruncateToCharLimit(f *testing.F) {
	f.Add("Hello world.", 280)
	f.Add("", 0)
	f.Add("你好世界", 500)
	f.Add(strings.Repeat("word ", 100), 10)
	f.Add("# Heading\nBody text here.", 50)
	f.Fuzz(func(t *testing.T, input string, limit int) {
		if limit < 0 {
			limit = -limit // normalize negative limits to positive
		}
		_ = truncateToCharLimit(input, limit) // must not panic
	})
}
