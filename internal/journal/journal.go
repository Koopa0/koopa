// Package journal provides journal entry storage for session logs.
//
// Journal entries are self-directed session logs: plans, context snapshots,
// reflections, and metrics. They are NOT cross-project coordination
// (that's directives/reports) and NOT hypothesis tracking (that's insights).
package journal

import (
	"errors"
	"time"
)

// ErrNotFound indicates the journal entry does not exist.
var ErrNotFound = errors.New("journal: not found")

// Kind represents a journal entry type.
type Kind string

const (
	KindPlan       Kind = "plan"
	KindContext    Kind = "context"
	KindReflection Kind = "reflection"
	KindMetrics    Kind = "metrics"
)

// Entry represents a journal entry.
type Entry struct {
	ID        int64          `json:"id"`
	Kind      Kind           `json:"kind"`
	Source    string         `json:"source"`
	Content   string         `json:"content"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	EntryDate time.Time      `json:"entry_date"`
	CreatedAt time.Time      `json:"created_at"`
}

// CreateParams holds the parameters for creating a journal entry.
type CreateParams struct {
	Kind      Kind
	Source    string
	Content   string
	Metadata  map[string]any
	EntryDate time.Time
}
