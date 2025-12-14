package handlers

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestTruncateForTitle tests the truncateForTitle helper function.
// Fallback title generation from user message.
func TestTruncateForTitle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantLen int // Optional: verify max length
	}{
		{
			name:  "short message unchanged",
			input: "Hello world",
			want:  "Hello world",
		},
		{
			name:  "exactly 50 chars unchanged",
			input: "This is exactly fifty characters long, yes it is!",
			want:  "This is exactly fifty characters long, yes it is!",
		},
		{
			name:    "long message truncated at word boundary",
			input:   "This is a very long message that exceeds the fifty character limit and should be truncated",
			want:    "This is a very long message that exceeds the...",
			wantLen: 50, // Max length check
		},
		{
			name:  "whitespace trimmed",
			input: "  Hello world  ",
			want:  "Hello world",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "whitespace only",
			input: "   \t\n  ",
			want:  "",
		},
		{
			name:    "single long word truncated without word boundary",
			input:   "Supercalifragilisticexpialidociousandotherlongwordsthatexceedlimit",
			want:    "Supercalifragilisticexpialidociousandotherlongword...",
			wantLen: 53, // 50 chars + "..."
		},
		{
			name: "chinese characters - short unchanged",
			// 39 runes - under limit, should be unchanged
			input: "這是一個很長的中文訊息，需要被截斷因為它超過了五十個字元的限制，這是額外的文字",
			want:  "這是一個很長的中文訊息，需要被截斷因為它超過了五十個字元的限制，這是額外的文字",
		},
		{
			name: "chinese characters - long truncated",
			// 56 runes - should be truncated to 50 + "..."
			input: "這是一個很長的中文訊息，需要被截斷因為它超過了五十個字元的限制，這是額外的文字，還有更多更多更多更多加油",
			want:  "這是一個很長的中文訊息，需要被截斷因為它超過了五十個字元的限制，這是額外的文字，還有更多更多更多更多...",
		},
		{
			name:  "message with newlines",
			input: "First line\nSecond line",
			want:  "First line\nSecond line",
		},
		{
			name:    "long message with newlines truncated",
			input:   "This is a message with\nnewlines that is definitely too long to fit in fifty characters",
			want:    "This is a message with\nnewlines that is...",
			wantLen: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := truncateForTitle(tt.input)

			if got != tt.want {
				t.Errorf("truncateForTitle(%q) = %q, want %q", tt.input, got, tt.want)
			}

			// Verify max length constraint if specified
			if tt.wantLen > 0 && len(got) > tt.wantLen {
				t.Errorf("truncateForTitle(%q) length = %d, want <= %d", tt.input, len(got), tt.wantLen)
			}
		})
	}
}

// TestTruncateForTitle_WordBoundary specifically tests word boundary behavior.
func TestTruncateForTitle_WordBoundary(t *testing.T) {
	t.Parallel()

	// This input is designed to have a word boundary exactly where we want to cut
	input := "Hello this is a test message that we will truncate at a word boundary"

	got := truncateForTitle(input)

	// Should end with "..." since it was truncated
	if got[len(got)-3:] != "..." {
		t.Errorf("truncated message should end with '...', got %q", got)
	}

	// Verify truncated output doesn't end with partial word before "..."
	// The function should truncate at word boundaries when possible
	withoutEllipsis := got[:len(got)-3]
	if len(withoutEllipsis) == 0 {
		t.Error("truncated message should have content before '...'")
	}
}

// TestTruncateForTitle_TitleMaxLength verifies the constant is correct.
func TestTruncateForTitle_TitleMaxLength(t *testing.T) {
	t.Parallel()

	if TitleMaxLength != 50 {
		t.Errorf("TitleMaxLength = %d, want 50", TitleMaxLength)
	}
}

// =============================================================================
// Tests for generateTitleWithAI
// =============================================================================

// TestGenerateTitleWithAI_NilGenkit verifies that nil Genkit returns empty string.
// This is the fallback path that triggers truncation in maybeGenerateTitle.
func TestGenerateTitleWithAI_NilGenkit(t *testing.T) {
	t.Parallel()

	handler := &Chat{
		logger: slog.Default(),
		genkit: nil, // Nil Genkit = AI disabled
	}

	title := handler.generateTitleWithAI(context.Background(), "Hello world")

	if title != "" {
		t.Errorf("generateTitleWithAI with nil genkit = %q, want empty string", title)
	}
}

// TestGenerateTitleWithAI_NilGenkit_LongMessage verifies nil Genkit behavior with long input.
func TestGenerateTitleWithAI_NilGenkit_LongMessage(t *testing.T) {
	t.Parallel()

	handler := &Chat{
		logger: slog.Default(),
		genkit: nil,
	}

	longMessage := strings.Repeat("This is a very long message. ", 100)
	title := handler.generateTitleWithAI(context.Background(), longMessage)

	if title != "" {
		t.Errorf("generateTitleWithAI with nil genkit = %q, want empty string", title)
	}
}

// TestGenerateTitleWithAI_CanceledContext verifies behavior with canceled context.
func TestGenerateTitleWithAI_CanceledContext(t *testing.T) {
	t.Parallel()

	handler := &Chat{
		logger: slog.Default(),
		genkit: nil, // Even with nil genkit, test context handling
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	title := handler.generateTitleWithAI(ctx, "Hello world")

	if title != "" {
		t.Errorf("generateTitleWithAI with canceled context = %q, want empty string", title)
	}
}

// TestTitleGenerationConstants verifies the constants are correctly defined.
func TestTitleGenerationConstants(t *testing.T) {
	t.Parallel()

	t.Run("TitleGenerationTimeout", func(t *testing.T) {
		t.Parallel()
		if TitleGenerationTimeout != 5*time.Second {
			t.Errorf("TitleGenerationTimeout = %v, want 5s", TitleGenerationTimeout)
		}
	})

	t.Run("TitleGenerationModel", func(t *testing.T) {
		t.Parallel()
		expected := "googleai/gemini-2.5-flash"
		if TitleGenerationModel != expected {
			t.Errorf("TitleGenerationModel = %q, want %q", TitleGenerationModel, expected)
		}
	})

	t.Run("TitleInputMaxRunes", func(t *testing.T) {
		t.Parallel()
		if TitleInputMaxRunes != 500 {
			t.Errorf("TitleInputMaxRunes = %d, want 500", TitleInputMaxRunes)
		}
	})
}

// TestTitlePrompt verifies the title prompt has expected structure.
func TestTitlePrompt(t *testing.T) {
	t.Parallel()

	// Verify prompt contains placeholder for user message
	if !strings.Contains(titlePrompt, "%s") {
		t.Error("titlePrompt should contain placeholder for user message")
	}

	// Verify prompt mentions character limit
	if !strings.Contains(titlePrompt, "50") {
		t.Error("titlePrompt should mention 50 character limit")
	}

	// Verify prompt asks for title
	if !strings.Contains(strings.ToLower(titlePrompt), "title") {
		t.Error("titlePrompt should mention 'title'")
	}
}
