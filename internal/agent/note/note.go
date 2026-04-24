// Package note provides an agent's internal narrative log — plans,
// context snapshots, and reflections. Agent-private notes, not cross-agent
// coordination (which lives in internal/agent/task).
package note

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound indicates the note does not exist.
var ErrNotFound = errors.New("agent note: not found")

// Kind mirrors the agent_note_kind SQL enum.
type Kind string

const (
	KindPlan       Kind = "plan"
	KindContext    Kind = "context"
	KindReflection Kind = "reflection"
)

// Note is an agent's narrative log entry.
type Note struct {
	ID        uuid.UUID      `json:"id"`
	Kind      Kind           `json:"kind"`
	CreatedBy string         `json:"created_by"`
	Content   string         `json:"content"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	EntryDate time.Time      `json:"entry_date"`
	CreatedAt time.Time      `json:"created_at"`
}

// CreateParams holds the parameters for creating a note.
type CreateParams struct {
	Kind      Kind
	CreatedBy string
	Content   string
	Metadata  map[string]any
	EntryDate time.Time
}
