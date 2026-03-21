// Package session provides cross-environment context bridging between
// Claude AI and Claude Code via session notes.
package session

import (
	"encoding/json"
	"errors"
	"time"
)

// ErrNotFound indicates no session note exists for the given query.
var ErrNotFound = errors.New("not found")

// Note represents a single session note (plan, reflection, context, or metrics).
type Note struct {
	ID        int64           `json:"id"`
	NoteDate  time.Time       `json:"note_date"`
	NoteType  string          `json:"note_type"`
	Source    string          `json:"source"`
	Content   string          `json:"content"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// CreateParams holds parameters for creating a session note.
type CreateParams struct {
	NoteDate time.Time
	NoteType string
	Source   string
	Content  string
	Metadata json.RawMessage
}
