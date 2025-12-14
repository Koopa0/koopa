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

// Role constants define valid message roles for type safety.
const (
	RoleUser  = "user"
	RoleModel = "model"
	RoleTool  = "tool"
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
	CanvasMode   bool // Per-session canvas mode preference
}

// Artifact represents a Canvas panel content item.
// Zero values:
//   - ID: uuid.Nil (invalid, must be generated)
//   - MessageID: nil (artifact not linked to message)
//   - Type: "" (invalid, validation required)
//   - Language: "" (no syntax highlighting)
//   - Title: "" (validation required - must have title)
//   - Version: 0 (will be set to 1 on create)
//   - SequenceNumber: 0 (auto-assigned on create)
type Artifact struct {
	ID             uuid.UUID
	SessionID      uuid.UUID
	MessageID      *uuid.UUID // Nullable - artifact may not be linked to a message
	Type           string     // "code" | "markdown" | "html"
	Language       string     // Programming language for code artifacts (optional)
	Title          string     // Filename or description
	Content        string     // Artifact content
	Version        int        // Version number for future editing
	SequenceNumber int        // Ordering for multiple artifacts
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Message represents a single conversation message (application-level type).
// Content field stores Genkit's ai.Part slice, serialized as JSONB in database.
type Message struct {
	ID             uuid.UUID
	SessionID      uuid.UUID
	Role           string     // "user" | "model" | "tool"
	Content        []*ai.Part // Genkit Part slice (stored as JSONB)
	Branch         string     // Branch name (default: "main")
	Status         string     // Message status: streaming/completed/failed
	SequenceNumber int
	CreatedAt      time.Time
}
