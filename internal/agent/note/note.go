// Package note provides an agent's internal narrative log — plans,
// context snapshots, and reflections. Renamed from "journal" in the
// coordination rebuild for semantic precision: these are agent-private
// notes, not cross-agent coordination (that lives in internal/task/).
//
// Import collision note: there is also internal/obsidian/note (Obsidian
// vault files). When both are needed in one file, alias one or both:
//
//	import (
//	    agentnote    "github.com/Koopa0/koopa0.dev/internal/agent/note"
//	    obsidiannote "github.com/Koopa0/koopa0.dev/internal/obsidian/note"
//	)
package note

import (
	"errors"
	"time"
)

// ErrNotFound indicates the note does not exist.
var ErrNotFound = errors.New("agent note: not found")

// Kind mirrors the agent_note_kind SQL enum. The old "metrics" kind has
// been removed — no current writer produced it, so it was dropped in the
// schema rebuild per the "don't implement for unverified scenarios" principle.
type Kind string

const (
	KindPlan       Kind = "plan"
	KindContext    Kind = "context"
	KindReflection Kind = "reflection"
)

// Note is an agent's narrative log entry.
type Note struct {
	ID        int64          `json:"id"`
	Kind      Kind           `json:"kind"`
	Author    string         `json:"author"`
	Content   string         `json:"content"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	EntryDate time.Time      `json:"entry_date"`
	CreatedAt time.Time      `json:"created_at"`
}

// CreateParams holds the parameters for creating a note.
type CreateParams struct {
	Kind      Kind
	Author    string
	Content   string
	Metadata  map[string]any
	EntryDate time.Time
}
