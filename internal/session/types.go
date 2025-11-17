// Package session provides session persistence functionality for conversation history.
//
// Responsibilities: Save/load conversation sessions to PostgreSQL database.
// Thread Safety: Not thread-safe - caller must synchronize access.
package session

import (
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
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
	Role           string      // "user" | "model" | "tool"
	Content        []*ai.Part  // Genkit Part slice (stored as JSONB)
	SequenceNumber int
	CreatedAt      time.Time
}
