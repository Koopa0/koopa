// Package session provides session persistence functionality for conversation history.
//
// Responsibilities: Save/load conversation sessions to PostgreSQL database.
// Thread Safety: Not thread-safe - caller must synchronize access.
package session

import (
	"sync"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
)

// History encapsulates conversation history with thread-safe access.
//
// Note: The zero value is NOT useful - use NewHistory() to create instances.
type History struct {
	mu       sync.RWMutex
	messages []*ai.Message
}

// NewHistory creates a new History instance.
func NewHistory() *History {
	return &History{
		messages: make([]*ai.Message, 0),
	}
}

// SetMessages replaces all messages in the history.
// Used by SessionStore when loading history from the database.
// Makes a defensive copy to prevent external modification.
func (h *History) SetMessages(messages []*ai.Message) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.messages = make([]*ai.Message, len(messages))
	copy(h.messages, messages)
}

// Messages returns a copy of all messages for thread-safe access
func (h *History) Messages() []*ai.Message {
	h.mu.RLock()
	defer h.mu.RUnlock()
	result := make([]*ai.Message, len(h.messages))
	copy(result, h.messages)
	return result
}

// Add appends user message and assistant response
func (h *History) Add(userInput, assistantResponse string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.messages = append(h.messages,
		ai.NewUserMessage(ai.NewTextPart(userInput)),
		ai.NewModelMessage(ai.NewTextPart(assistantResponse)),
	)
}

// AddMessage appends a single message
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

// Role constants define valid message roles for type safety.
const (
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
)

// Session represents a conversation session (application-level type).
type Session struct {
	ID           uuid.UUID
	Title        string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ModelName    string
	SystemPrompt string
	MessageCount int
}

// Message represents a single conversation message (application-level type).
// Content field stores Genkit's ai.Part slice, serialized as JSONB in database.
type Message struct {
	ID             uuid.UUID
	SessionID      uuid.UUID
	Role           string     // "user" | "assistant" | "tool"
	Content        []*ai.Part // Genkit Part slice (stored as JSONB)
	Status         string     // Message status: streaming/completed/failed
	SequenceNumber int
	CreatedAt      time.Time
}
