package agent

import (
	"github.com/firebase/genkit/go/ai"
)

// History encapsulates conversation history
type History struct {
	messages []*ai.Message
}

// NewHistory creates a new History instance
func NewHistory() *History {
	return &History{
		messages: make([]*ai.Message, 0),
	}
}

// NewHistoryFromMessages creates History from existing messages
// Used by SessionStore when loading history
func NewHistoryFromMessages(messages []*ai.Message) *History {
	return &History{
		messages: messages,
	}
}

// Messages returns all messages
func (h *History) Messages() []*ai.Message {
	return h.messages
}

// Add appends user message and assistant response
func (h *History) Add(userInput string, assistantResponse string) {
	h.messages = append(h.messages,
		ai.NewUserMessage(ai.NewTextPart(userInput)),
		ai.NewModelMessage(ai.NewTextPart(assistantResponse)),
	)
}

// AddMessage appends a single message
// Provides fine-grained control for adding system messages
func (h *History) AddMessage(msg *ai.Message) {
	h.messages = append(h.messages, msg)
}

// Count returns the number of messages
func (h *History) Count() int {
	return len(h.messages)
}

// Clear removes all messages
func (h *History) Clear() {
	h.messages = make([]*ai.Message, 0)
}
