package agent

import (
	"sync"

	"github.com/firebase/genkit/go/ai"
)

// History encapsulates conversation history with thread-safe access
type History struct {
	mu       sync.RWMutex
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

// Messages returns a copy of all messages for thread-safe access
func (h *History) Messages() []*ai.Message {
	h.mu.RLock()
	defer h.mu.RUnlock()
	// Return a copy to prevent external modification
	result := make([]*ai.Message, len(h.messages))
	copy(result, h.messages)
	return result
}

// Add appends user message and assistant response
func (h *History) Add(userInput string, assistantResponse string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.messages = append(h.messages,
		ai.NewUserMessage(ai.NewTextPart(userInput)),
		ai.NewModelMessage(ai.NewTextPart(assistantResponse)),
	)
}

// AddMessage appends a single message
// Provides fine-grained control for adding system messages
// Returns without effect if msg is nil
func (h *History) AddMessage(msg *ai.Message) {
	if msg == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.messages = append(h.messages, msg)
}

// Count returns the number of messages
func (h *History) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.messages)
}

// Clear removes all messages
func (h *History) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.messages = make([]*ai.Message, 0)
}
