package session

import (
	"errors"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
)

// TitleMaxLength is the maximum rune length for a session title.
const TitleMaxLength = 50

// ErrNotFound indicates the requested session does not exist in the database.
var ErrNotFound = errors.New("session not found")

// Session represents a conversation session (application-level type).
type Session struct {
	ID           uuid.UUID
	OwnerID      string
	Title        string
	MessageCount int // Populated by Sessions() list query; zero otherwise.
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ExportData is the full session export with all messages.
// The API handler uses a DTO to control which fields are serialized.
type ExportData struct {
	Session  *Session
	Messages []*Message
}

// SearchResult represents a single full-text search match across sessions.
type SearchResult struct {
	SessionID    uuid.UUID `json:"session_id"`
	SessionTitle string    `json:"session_title"`
	MessageID    uuid.UUID `json:"message_id"`
	Role         string    `json:"role"`
	Snippet      string    `json:"snippet"`
	CreatedAt    time.Time `json:"created_at"`
	Rank         float64   `json:"rank"`
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

// Text concatenates all text parts in the message content.
func (m *Message) Text() string {
	var b strings.Builder
	for _, part := range m.Content {
		if part != nil {
			b.WriteString(part.Text)
		}
	}
	return b.String()
}
