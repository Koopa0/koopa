package chat

import (
	"slices"
	"unicode/utf8"

	"github.com/firebase/genkit/go/ai"
)

// TokenBudget manages context window limits.
type TokenBudget struct {
	MaxHistoryTokens int // Maximum tokens for conversation history
}

// DefaultTokenBudget returns conservative defaults for Gemini models.
func DefaultTokenBudget() TokenBudget {
	return TokenBudget{
		MaxHistoryTokens: 8000, // ~8K tokens for history
	}
}

// estimateTokens provides a rough token count.
// Uses rune count divided by 2 as a conservative estimate that works
// for both English (~4 chars/token) and CJK (~1.5 chars/token) text.
// Returns at least 1 for any non-empty text to avoid zero-cost messages
// breaking token budget calculations.
func estimateTokens(text string) int {
	runeCount := utf8.RuneCountInString(text)
	if runeCount == 0 {
		return 0
	}
	tokens := runeCount / 2
	if tokens == 0 {
		return 1
	}
	return tokens
}

// estimateMessagesTokens estimates total tokens in messages.
func estimateMessagesTokens(msgs []*ai.Message) int {
	total := 0
	for _, msg := range msgs {
		for _, part := range msg.Content {
			total += estimateTokens(part.Text)
		}
	}
	return total
}

// truncateHistory removes oldest messages to fit within budget.
// Preserves system message (if present) and keeps most recent messages.
func (c *Chat) truncateHistory(msgs []*ai.Message, budget int) []*ai.Message {
	if len(msgs) == 0 {
		return msgs
	}

	currentTokens := estimateMessagesTokens(msgs)
	if currentTokens <= budget {
		return msgs
	}

	c.logger.Debug("truncating history",
		"current_tokens", currentTokens,
		"budget", budget,
		"message_count", len(msgs),
	)

	// Keep system message (first) and recent messages
	// Remove from the middle (oldest non-system messages)
	result := make([]*ai.Message, 0, len(msgs))

	// Always keep system message if present
	startIdx := 0
	if len(msgs) > 0 && msgs[0].Role == ai.RoleSystem {
		result = append(result, msgs[0])
		startIdx = 1
	}

	// Add messages from newest to oldest until budget exhausted
	remaining := budget - estimateMessagesTokens(result)
	kept := make([]*ai.Message, 0)
	for i := len(msgs) - 1; i >= startIdx; i-- {
		msgTokens := estimateMessagesTokens([]*ai.Message{msgs[i]})
		if remaining < msgTokens {
			continue
		}
		kept = append(kept, msgs[i])
		remaining -= msgTokens
	}
	// Reverse to restore chronological order (O(n) instead of O(n²) prepend)
	slices.Reverse(kept)
	// Append kept messages after system message
	result = append(result, kept...)

	c.logger.Debug("history truncated",
		"original_count", len(msgs),
		"new_count", len(result),
		"tokens_used", budget-remaining,
	)

	return result
}
