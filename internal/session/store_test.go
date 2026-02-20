package session

import (
	"testing"

	"github.com/firebase/genkit/go/ai"
)

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

// TestEscapeLike verifies LIKE metacharacter escaping.
// Backslash must be escaped first to prevent double-escaping of % and _ escapes.
func TestEscapeLike(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "no metacharacters", input: "hello world", want: "hello world"},
		{name: "percent", input: "100%", want: `100\%`},
		{name: "underscore", input: "a_b", want: `a\_b`},
		{name: "backslash", input: `a\b`, want: `a\\b`},
		{name: "all metacharacters", input: `%_\`, want: `\%\_\\`},
		{name: "backslash before percent", input: `\%`, want: `\\\%`},
		{name: "backslash before underscore", input: `\_`, want: `\\\_`},
		{name: "already double escaped", input: `\\%`, want: `\\\\\%`},
		{name: "CJK passthrough", input: "搜尋測試", want: "搜尋測試"},
		{name: "CJK with underscore", input: "用戶_名稱", want: `用戶\_名稱`},
		{name: "multiple percent", input: "%%", want: `\%\%`},
		{name: "mixed content", input: `50% off_sale\today`, want: `50\% off\_sale\\today`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := escapeLike(tt.input)
			if got != tt.want {
				t.Errorf("escapeLike(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestDenormalizeRole verifies the reverse of normalizeRole.
// Database stores "assistant" but Genkit/Gemini API requires "model".
func TestDenormalizeRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "assistant to model", input: "assistant", want: "model"},
		{name: "user unchanged", input: "user", want: "user"},
		{name: "model unchanged", input: "model", want: "model"},
		{name: "system unchanged", input: "system", want: "system"},
		{name: "tool unchanged", input: "tool", want: "tool"},
		{name: "empty passthrough", input: "", want: ""},
		{name: "unknown passthrough", input: "unknown", want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := denormalizeRole(tt.input)
			if got != tt.want {
				t.Errorf("denormalizeRole(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestExtractTextContent verifies text extraction from ai.Part slices
// for full-text search indexing.
func TestExtractTextContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		parts []*ai.Part
		want  string
	}{
		{name: "nil slice", parts: nil, want: ""},
		{name: "empty slice", parts: []*ai.Part{}, want: ""},
		{name: "single text part", parts: []*ai.Part{ai.NewTextPart("hello")}, want: "hello"},
		{name: "multiple text parts", parts: []*ai.Part{
			ai.NewTextPart("hello"),
			ai.NewTextPart("world"),
		}, want: "hello world"},
		{name: "nil part skipped", parts: []*ai.Part{
			ai.NewTextPart("before"),
			nil,
			ai.NewTextPart("after"),
		}, want: "before after"},
		{name: "empty text skipped", parts: []*ai.Part{
			ai.NewTextPart("content"),
			ai.NewTextPart(""),
			ai.NewTextPart("more"),
		}, want: "content more"},
		{name: "CJK text", parts: []*ai.Part{
			ai.NewTextPart("你好"),
			ai.NewTextPart("世界"),
		}, want: "你好 世界"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractTextContent(tt.parts)
			if got != tt.want {
				t.Errorf("extractTextContent() = %q, want %q", got, tt.want)
			}
		})
	}
}
