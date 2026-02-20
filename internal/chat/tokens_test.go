package chat

import (
	"log/slog"
	"testing"

	"github.com/firebase/genkit/go/ai"
)

func TestDefaultTokenBudget(t *testing.T) {
	t.Parallel()

	budget := DefaultTokenBudget()

	if budget.MaxHistoryTokens <= 0 {
		t.Error("MaxHistoryTokens should be positive")
	}
}

func TestEstimateTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		text string
		want int
	}{
		{
			name: "empty string",
			text: "",
			want: 0,
		},
		{
			name: "single char returns 1",
			text: "a",
			want: 1, // 1 rune / 2 = 0, but min 1 for non-empty
		},
		{
			name: "short english",
			text: "hello",
			want: 2, // 5 runes / 2 = 2
		},
		{
			name: "longer english",
			text: "This is a longer test message with multiple words.",
			want: 25, // 50 runes / 2 = 25
		},
		{
			name: "cjk text",
			text: "你好世界",
			want: 2, // 4 runes / 2 = 2
		},
		{
			name: "mixed text",
			text: "Hello 世界",
			want: 4, // 8 runes / 2 = 4
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := estimateTokens(tt.text)
			if got != tt.want {
				t.Errorf("estimateTokens(%q) = %d, want %d", tt.text, got, tt.want)
			}
		})
	}
}

func TestEstimateMessagesTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		msgs []*ai.Message
		want int
	}{
		{
			name: "nil messages",
			msgs: nil,
			want: 0,
		},
		{
			name: "empty messages",
			msgs: []*ai.Message{},
			want: 0,
		},
		{
			name: "single message",
			msgs: []*ai.Message{
				ai.NewUserMessage(ai.NewTextPart("hello world")), // 11 runes / 2 = 5
			},
			want: 5,
		},
		{
			name: "multiple messages",
			msgs: []*ai.Message{
				ai.NewUserMessage(ai.NewTextPart("hello")),       // 5 / 2 = 2
				ai.NewModelMessage(ai.NewTextPart("world")),      // 5 / 2 = 2
				ai.NewUserMessage(ai.NewTextPart("how are you")), // 11 / 2 = 5
			},
			want: 9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := estimateMessagesTokens(tt.msgs)
			if got != tt.want {
				t.Errorf("estimateMessagesTokens() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestTruncateHistory(t *testing.T) {
	t.Parallel()

	// Helper to create a Chat with nop logger for testing
	makeAgent := func() *Agent {
		return &Agent{
			logger: slog.New(slog.DiscardHandler),
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
				systemMsg("You are a helpful assistant"), // 13 tokens
				userMsg("first"),                         // 2 tokens
				modelMsg("second"),                       // 3 tokens
				userMsg("third"),                         // 2 tokens
				modelMsg("fourth"),                       // 3 tokens
			},
			budget:        20, // Room for system(13) + first(2) + third(2) + fourth(3) = 20, skips second(3)
			wantLen:       4,  // System + first + third + fourth (second skipped)
			wantHasSystem: true,
			wantLastText:  "fourth",
			wantTexts:     []string{"You are a helpful assistant", "first", "third", "fourth"},
		},
		{
			name: "skips large message but keeps surrounding small ones",
			msgs: []*ai.Message{
				userMsg("hi"), // 1 token
				modelMsg("This is a very long response that takes many many tokens in the budget and should be skipped"), // ~46 tokens
				userMsg("ok"),   // 1 token
				modelMsg("bye"), // 1 token
			},
			budget:       5,
			wantLen:      3,
			wantLastText: "bye",
			wantTexts:    []string{"hi", "ok", "bye"}, // Large msg2 skipped, small msgs kept
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

			agent := makeAgent()
			got := agent.truncateHistory(tt.msgs, tt.budget)

			if len(got) != tt.wantLen {
				t.Errorf("truncateHistory() len = %d, want %d", len(got), tt.wantLen)
			}

			if tt.wantLen == 0 {
				return
			}

			// Check system message preservation
			if tt.wantHasSystem {
				if got[0].Role != ai.RoleSystem {
					t.Errorf("want first message to be system, got %s", got[0].Role)
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
					t.Fatalf("got %d messages but want %d texts to verify", len(got), len(tt.wantTexts))
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

func TestTruncateHistory_EdgeCases(t *testing.T) {
	t.Parallel()

	makeAgent := func() *Agent {
		return &Agent{logger: slog.New(slog.DiscardHandler)}
	}

	systemMsg := func(text string) *ai.Message {
		return ai.NewSystemMessage(ai.NewTextPart(text))
	}
	userMsg := func(text string) *ai.Message {
		return ai.NewUserMessage(ai.NewTextPart(text))
	}
	modelMsg := func(text string) *ai.Message {
		return ai.NewModelMessage(ai.NewTextPart(text))
	}

	tests := []struct {
		name      string
		msgs      []*ai.Message
		budget    int
		wantLen   int
		wantTexts []string
	}{
		{
			name: "budget zero drops all non-system",
			msgs: []*ai.Message{
				userMsg("hello"),
				modelMsg("world"),
			},
			budget:    0,
			wantLen:   0,
			wantTexts: nil,
		},
		{
			name: "negative budget drops all non-system",
			msgs: []*ai.Message{
				userMsg("hello"),
				modelMsg("world"),
			},
			budget:    -100,
			wantLen:   0,
			wantTexts: nil,
		},
		{
			name: "budget zero with system message keeps only system",
			msgs: []*ai.Message{
				systemMsg("system"),
				userMsg("hello"),
				modelMsg("world"),
			},
			budget:    10, // system = 3 tokens, fits; user+model don't fit in remaining 7
			wantLen:   3,
			wantTexts: []string{"system", "hello", "world"},
		},
		{
			name: "system message alone exceeds budget",
			msgs: []*ai.Message{
				systemMsg("This is a very long system prompt that uses many tokens"),
				userMsg("hi"),
			},
			budget:    2, // System alone is ~25 tokens, way over budget
			wantLen:   1, // System always kept; remaining budget negative → no more msgs
			wantTexts: []string{"This is a very long system prompt that uses many tokens"},
		},
		{
			name: "single message under budget",
			msgs: []*ai.Message{
				userMsg("hi"),
			},
			budget:    100,
			wantLen:   1,
			wantTexts: []string{"hi"},
		},
		{
			name: "single message over budget returns empty",
			msgs: []*ai.Message{
				userMsg("this message exceeds the tiny budget"),
			},
			budget:    1,
			wantLen:   0,
			wantTexts: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			agent := makeAgent()
			got := agent.truncateHistory(tt.msgs, tt.budget)

			if len(got) != tt.wantLen {
				t.Fatalf("truncateHistory(budget=%d) len = %d, want %d", tt.budget, len(got), tt.wantLen)
			}

			if tt.wantTexts != nil {
				for i, want := range tt.wantTexts {
					if len(got[i].Content) == 0 {
						t.Fatalf("message %d has no content", i)
					}
					if got[i].Content[0].Text != want {
						t.Errorf("message %d text = %q, want %q", i, got[i].Content[0].Text, want)
					}
				}
			}
		})
	}
}

func TestEstimateTokens_SpecialCharacters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		text string
		want int
	}{
		{
			name: "emoji single",
			text: "😀",
			want: 1, // 1 rune / 2 = 0, min 1
		},
		{
			name: "emoji sequence",
			text: "😀😁😂🤣😃",
			want: 2, // 5 runes / 2 = 2
		},
		{
			name: "emoji with text",
			text: "hello 👋 world 🌍",
			want: 7, // 15 runes / 2 = 7
		},
		{
			name: "zero-width joiner sequence",
			text: "👨‍👩‍👧‍👦", // family emoji with ZWJ, multiple runes
			want: 3,         // 7 runes (4 emoji + 3 ZWJ) / 2 = 3
		},
		{
			name: "CJK mixed with ASCII",
			text: "Go語言は素晴らしい",
			want: 5, // 10 runes / 2 = 5
		},
		{
			name: "pure CJK sentence",
			text: "人工知能の未来について",
			want: 5, // 10 runes / 2 = 5
		},
		{
			name: "zero-width space",
			text: "hello\u200Bworld", // zero-width space between
			want: 5,                  // 11 runes / 2 = 5
		},
		{
			name: "combining diacriticals",
			text: "e\u0301", // é as e + combining acute accent = 2 runes
			want: 1,         // 2 runes / 2 = 1
		},
		{
			name: "only whitespace",
			text: "   ",
			want: 1, // 3 runes / 2 = 1
		},
		{
			name: "newlines and tabs",
			text: "line1\nline2\tline3",
			want: 8, // 17 runes / 2 = 8
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := estimateTokens(tt.text)
			if got != tt.want {
				t.Errorf("estimateTokens(%q) = %d, want %d", tt.text, got, tt.want)
			}
		})
	}
}

func TestTruncateHistory_ChronologicalOrder(t *testing.T) {
	t.Parallel()

	agent := &Agent{logger: slog.New(slog.DiscardHandler)}

	// Create a conversation with alternating user/model messages
	msgs := []*ai.Message{
		ai.NewUserMessage(ai.NewTextPart("msg1")),
		ai.NewModelMessage(ai.NewTextPart("msg2")),
		ai.NewUserMessage(ai.NewTextPart("msg3")),
		ai.NewModelMessage(ai.NewTextPart("msg4")),
		ai.NewUserMessage(ai.NewTextPart("msg5")),
	}

	// Budget should keep only last 2-3 messages
	result := agent.truncateHistory(msgs, 6)

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
