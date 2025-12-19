package artifact

import (
	"time"

	"github.com/google/uuid"
)

// Type represents the artifact content type.
type Type string

const (
	TypeCode     Type = "code"
	TypeMarkdown Type = "markdown"
	TypeHTML     Type = "html"
)

// Artifact represents Canvas panel content.
//
// Each Artifact is identified by (SessionID, Filename).
// Filename must be unique within a session.
//
// Zero values:
//   - ID: uuid.Nil (invalid, must be generated)
//   - SessionID: uuid.Nil (invalid, required)
//   - MessageID: nil (artifact not linked to a message)
//   - Filename: "" (invalid, required)
//   - Type: "" (invalid, must be one of TypeCode, TypeMarkdown, TypeHTML)
//   - Language: "" (no syntax highlighting)
//   - Title: "" (display title, optional)
//   - Content: "" (empty content allowed)
//   - Version: 0 (reserved for future versioning)
//   - SequenceNumber: 0 (auto-assigned on create)
type Artifact struct {
	ID             uuid.UUID
	SessionID      uuid.UUID
	MessageID      *uuid.UUID // Optional: linked message for traceability
	Filename       string     // Unique within session (e.g., "main.go", "report.md")
	Type           Type
	Language       string // Programming language for code artifacts
	Title          string // Display title
	Content        string
	Version        int // Reserved for future versioning
	SequenceNumber int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
