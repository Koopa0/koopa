package session

import (
	"errors"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
)

// ErrNotFound indicates the requested session does not exist in the database.
var ErrNotFound = errors.New("session not found")

// Session represents a conversation session (application-level type).
type Session struct {
	ID        uuid.UUID
	OwnerID   string
	Title     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Message represents a single conversation message (application-level type).
// Content field stores Genkit's ai.Part slice, serialized as JSONB in database.
type Message struct {
	ID             uuid.UUID
	SessionID      uuid.UUID
	Role           string     // "user" | "assistant" | "system" | "tool"
	Content        []*ai.Part // Genkit Part slice (stored as JSONB)
	SequenceNumber int
	CreatedAt      time.Time
}
