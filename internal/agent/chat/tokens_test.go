package chat

import (
	"testing"

	"github.com/firebase/genkit/go/ai"

	"github.com/koopa0/koopa/internal/log"
)

func TestDefaultTokenBudget(t *testing.T) {
	t.Parallel()

	budget := DefaultTokenBudget()

	if budget.MaxHistoryTokens <= 0 {
		t.Error("MaxHistoryTokens should be positive")
	}
	if budget.MaxInputTokens <= 0 {
		t.Error("MaxInputTokens should be positive")
	}
	if budget.ReservedTokens <= 0 {
		t.Error("ReservedTokens should be positive")
	}
}

func TestEstimateTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		text     string
		expected int
	}{
		{
			name:     "empty string",
			text:     "",
			expected: 0,
		},
		{
			name:     "short english",
			text:     "hello",
			expected: 2, // 5 runes / 2 = 2
		},
		{
			name:     "longer english",
			text:     "This is a longer test message with multiple words.",
			expected: 25, // 50 runes / 2 = 25
		},
		{
			name:     "cjk text",
			text:     "你好世界",
			expected: 2, // 4 runes / 2 = 2
		},
		{
			name:     "mixed text",
			text:     "Hello 世界",
			expected: 4, // 8 runes / 2 = 4
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := estimateTokens(tt.text)
			if got != tt.expected {
				t.Errorf("estimateTokens(%q) = %d, want %d", tt.text, got, tt.expected)
			}
		})
	}
}

func TestEstimateMessagesTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		msgs     []*ai.Message
		expected int
	}{
		{
			name:     "nil messages",
			msgs:     nil,
			expected: 0,
		},
		{
			name:     "empty messages",
			msgs:     []*ai.Message{},
			expected: 0,
		},
		{
			name: "single message",
			msgs: []*ai.Message{
				ai.NewUserMessage(ai.NewTextPart("hello world")), // 11 runes / 2 = 5
			},
			expected: 5,
		},
		{
			name: "multiple messages",
			msgs: []*ai.Message{
				ai.NewUserMessage(ai.NewTextPart("hello")),       // 5 / 2 = 2
				ai.NewModelMessage(ai.NewTextPart("world")),      // 5 / 2 = 2
				ai.NewUserMessage(ai.NewTextPart("how are you")), // 11 / 2 = 5
			},
			expected: 9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := estimateMessagesTokens(tt.msgs)
			if got != tt.expected {
				t.Errorf("estimateMessagesTokens() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestTruncateHistory(t *testing.T) {
	t.Parallel()

	// Helper to create a Chat with nop logger for testing
	makeChat := func() *Chat {
		return &Chat{
			logger: log.NewNop(),
		}
	}

	// Helper to create a system message
	systemMsg := func(text string) *ai.Message {
		return ai.NewSystemMessage(ai.NewTextPart(text))
	}

	// Helper to create user/model messages
	userMsg := func(text string) *ai.Message {
		return ai.NewUserMessage(ai.NewTextPart(text))
	}
	modelMsg := func(text string) *ai.Message {
		return ai.NewModelMessage(ai.NewTextPart(text))
	}

	tests := []struct {
		name          string
		msgs          []*ai.Message
		budget        int
		wantLen       int
		wantHasSystem bool     // Should result start with system message?
		wantLastText  string   // Expected text of last message
		wantTexts     []string // Expected texts of all retained messages (verifies specific messages kept)
	}{
		{
			name:    "nil messages returns nil",
			msgs:    nil,
			budget:  1000,
			wantLen: 0,
		},
		{
			name:    "empty messages returns empty",
			msgs:    []*ai.Message{},
			budget:  1000,
			wantLen: 0,
		},
		{
			name: "under budget returns all",
			msgs: []*ai.Message{
				userMsg("hello"),       // 2 tokens
				modelMsg("hi there"),   // 4 tokens
				userMsg("how are you"), // 5 tokens
			},
			budget:       100, // Way over what's needed
			wantLen:      3,
			wantLastText: "how are you",
			wantTexts:    []string{"hello", "hi there", "how are you"}, // Verify order preserved
		},
		{
			name: "over budget truncates oldest",
			msgs: []*ai.Message{
				userMsg("first message"), // 6 tokens
				modelMsg("second msg"),   // 5 tokens
				userMsg("third message"), // 6 tokens
				modelMsg("fourth final"), // 6 tokens
			},
			budget:       12, // Only room for ~2 messages
			wantLen:      2,
			wantLastText: "fourth final",
			wantTexts:    []string{"third message", "fourth final"}, // Verify specific messages retained
		},
		{
			name: "preserves system message when truncating",
			msgs: []*ai.Message{
				systemMsg("You are a helpful assistant"), // 14 tokens
				userMsg("first"),                         // 2 tokens
				modelMsg("second"),                       // 3 tokens
				userMsg("third"),                         // 2 tokens
				modelMsg("fourth"),                       // 3 tokens
			},
			budget:        20, // Room for system + ~2 messages
			wantLen:       3,  // System + 2 recent
			wantHasSystem: true,
			wantLastText:  "fourth",
			wantTexts:     []string{"You are a helpful assistant", "third", "fourth"}, // System + recent, in order
		},
		{
			name: "maintains chronological order after truncation",
			msgs: []*ai.Message{
				userMsg("oldest"),  // 3 tokens
				modelMsg("older"),  // 2 tokens
				userMsg("newer"),   // 2 tokens
				modelMsg("newest"), // 3 tokens
			},
			budget:       8, // Room for ~2-3 messages
			wantLen:      3,
			wantLastText: "newest",
			wantTexts:    []string{"older", "newer", "newest"}, // Verify correct subset retained
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			chat := makeChat()
			got := chat.truncateHistory(tt.msgs, tt.budget)

			if len(got) != tt.wantLen {
				t.Errorf("truncateHistory() len = %d, want %d", len(got), tt.wantLen)
			}

			if tt.wantLen == 0 {
				return
			}

			// Check system message preservation
			if tt.wantHasSystem {
				if got[0].Role != ai.RoleSystem {
					t.Errorf("expected first message to be system, got %s", got[0].Role)
				}
			}

			// Check last message text
			if tt.wantLastText != "" {
				lastMsg := got[len(got)-1]
				if len(lastMsg.Content) == 0 {
					t.Fatal("last message has no content")
				}
				if lastMsg.Content[0].Text != tt.wantLastText {
					t.Errorf("last message text = %q, want %q", lastMsg.Content[0].Text, tt.wantLastText)
				}
			}

			// Check all retained message texts AND ORDER (verifies correct subset kept in chronological order)
			// wantTexts[i] must match got[i] - this implicitly verifies ordering
			if len(tt.wantTexts) > 0 {
				if len(got) != len(tt.wantTexts) {
					t.Fatalf("got %d messages but expected %d texts to verify", len(got), len(tt.wantTexts))
				}
				for i, want := range tt.wantTexts {
					if len(got[i].Content) == 0 {
						t.Fatalf("message %d has no content", i)
					}
					gotText := got[i].Content[0].Text
					if gotText != want {
						t.Errorf("message %d text = %q, want %q", i, gotText, want)
					}
				}
			}
		})
	}
}

func TestTruncateHistory_ChronologicalOrder(t *testing.T) {
	t.Parallel()

	chat := &Chat{logger: log.NewNop()}

	// Create a conversation with alternating user/model messages
	msgs := []*ai.Message{
		ai.NewUserMessage(ai.NewTextPart("msg1")),
		ai.NewModelMessage(ai.NewTextPart("msg2")),
		ai.NewUserMessage(ai.NewTextPart("msg3")),
		ai.NewModelMessage(ai.NewTextPart("msg4")),
		ai.NewUserMessage(ai.NewTextPart("msg5")),
	}

	// Budget should keep only last 2-3 messages
	result := chat.truncateHistory(msgs, 6)

	// Verify messages are still in chronological order
	for i := 1; i < len(result); i++ {
		prevText := result[i-1].Content[0].Text
		currText := result[i].Content[0].Text

		// Messages should be in order (msg3 < msg4 < msg5, etc.)
		if prevText >= currText {
			t.Errorf("messages not in chronological order: %q >= %q", prevText, currText)
		}
	}
}
