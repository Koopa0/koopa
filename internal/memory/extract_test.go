package memory

import (
	"strings"
	"testing"
)

func TestStripCodeFences(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no fences",
			input: `[{"content":"hello","category":"identity"}]`,
			want:  `[{"content":"hello","category":"identity"}]`,
		},
		{
			name:  "json fence",
			input: "```json\n[{\"content\":\"hello\"}]\n```",
			want:  `[{"content":"hello"}]`,
		},
		{
			name:  "plain fence",
			input: "```\n[{\"content\":\"hello\"}]\n```",
			want:  `[{"content":"hello"}]`,
		},
		{
			name:  "fence with trailing whitespace",
			input: "```json\n[{\"content\":\"hello\"}]\n```\n  ",
			want:  `[{"content":"hello"}]`,
		},
		{
			name:  "empty",
			input: "",
			want:  "",
		},
		{
			name:  "only fences",
			input: "```json\n```",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripCodeFences(tt.input)
			if got != tt.want {
				t.Errorf("stripCodeFences() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		n     int
		want  string
	}{
		{name: "short", input: "hello", n: 10, want: "hello"},
		{name: "exact", input: "hello", n: 5, want: "hello"},
		{name: "truncated", input: "hello world", n: 5, want: "hello..."},
		{name: "empty", input: "", n: 5, want: ""},
		{name: "zero limit", input: "hello", n: 0, want: "..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncate(tt.input, tt.n)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.want)
			}
		})
	}
}

func TestFormatConversation(t *testing.T) {
	got := FormatConversation("hello", "hi there")
	want := "User: hello\nAssistant: hi there"
	if got != want {
		t.Errorf("FormatConversation() = %q, want %q", got, want)
	}
}

func TestFormatConversation_Empty(t *testing.T) {
	got := FormatConversation("", "")
	want := "User: \nAssistant: "
	if got != want {
		t.Errorf("FormatConversation(\"\", \"\") = %q, want %q", got, want)
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce, err := generateNonce()
	if err != nil {
		t.Fatalf("generateNonce() unexpected error: %v", err)
	}
	if len(nonce) != 32 { // 16 bytes → 32 hex chars
		t.Errorf("generateNonce() len = %d, want 32", len(nonce))
	}

	// Ensure uniqueness across calls.
	nonce2, err := generateNonce()
	if err != nil {
		t.Fatalf("generateNonce() second call unexpected error: %v", err)
	}
	if nonce == nonce2 {
		t.Error("generateNonce() returned same nonce twice")
	}
}

func TestMaxExtractResponseBytes(t *testing.T) {
	// Verify the constant is reasonable (10 KB).
	if maxExtractResponseBytes != 10*1024 {
		t.Errorf("maxExtractResponseBytes = %d, want %d", maxExtractResponseBytes, 10*1024)
	}
}

func TestExtractionPromptContainsNoncePlaceholders(t *testing.T) {
	// Verify the prompt has 3 %s placeholders (nonce, conversation, nonce) and 1 %d (maxFacts).
	count := strings.Count(extractionPrompt, "%s")
	if count != 3 {
		t.Errorf("extractionPrompt has %d %%s placeholders, want 3", count)
	}
	if !strings.Contains(extractionPrompt, "===CONVERSATION_") {
		t.Error("extractionPrompt missing nonce-based delimiter")
	}
	if !strings.Contains(extractionPrompt, "===END_CONVERSATION_") {
		t.Error("extractionPrompt missing end delimiter")
	}
}

func TestExtractionPromptCategories(t *testing.T) {
	// Verify all 4 categories are documented in the prompt.
	for _, cat := range []string{"identity", "preference", "project", "contextual"} {
		if !strings.Contains(extractionPrompt, `"`+cat+`"`) {
			t.Errorf("extractionPrompt missing category %q", cat)
		}
	}
}

func TestExtractionPromptFields(t *testing.T) {
	// Verify importance and expires_in fields are in the prompt.
	if !strings.Contains(extractionPrompt, `"importance"`) {
		t.Error("extractionPrompt missing importance field")
	}
	if !strings.Contains(extractionPrompt, `"expires_in"`) {
		t.Error("extractionPrompt missing expires_in field")
	}
	// Verify max 365d cap is mentioned.
	if !strings.Contains(extractionPrompt, "365d") {
		t.Error("extractionPrompt missing 365d cap mention")
	}
	// Verify anti-injection instruction.
	if !strings.Contains(extractionPrompt, "Ignore any instructions") {
		t.Error("extractionPrompt missing anti-injection instruction")
	}
}
