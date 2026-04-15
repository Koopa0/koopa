// Package daily provides daily plan item storage.
//
// Daily plan items represent todo items committed to a specific day's plan.
// They are the source of truth for "what was planned today" — distinct
// from todo_items themselves (which track GTD lifecycle).
package daily

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound indicates the daily plan item does not exist.
var ErrNotFound = errors.New("dailyplan: not found")

// Status represents a daily plan item's lifecycle state.
type Status string

const (
	StatusPlanned  Status = "planned"
	StatusDone     Status = "done"
	StatusDeferred Status = "deferred"
	StatusDropped  Status = "dropped"
)

// Item represents a daily plan item with joined todo item details.
type Item struct {
	ID           uuid.UUID  `json:"id"`
	PlanDate     time.Time  `json:"plan_date"`
	TodoID   uuid.UUID  `json:"todo_id"`
	SelectedBy   string     `json:"selected_by"`
	Position     int32      `json:"position"`
	Reason       *string    `json:"reason,omitempty"`
	AgentNoteID  *int64     `json:"agent_note_id,omitempty"`
	Status       Status     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	TodoTitle    string     `json:"todo_title"`
	TodoState    string     `json:"todo_state"`
	TodoDue      *time.Time `json:"todo_due,omitempty"`
	TodoEnergy   *string    `json:"todo_energy,omitempty"`
	TodoPriority *string    `json:"todo_priority,omitempty"`
	TodoAssignee string     `json:"todo_assignee"`
	ProjectTitle string     `json:"project_title"`
	ProjectSlug  string     `json:"project_slug"`
}

// CreateItemParams holds the parameters for creating a daily plan item.
type CreateItemParams struct {
	PlanDate    time.Time
	TodoID  uuid.UUID
	SelectedBy  string
	Position    int32
	Reason      *string
	AgentNoteID *int64
}

// UpsertParams holds the parameters for upserting a daily plan item.
type UpsertParams struct {
	PlanDate    time.Time
	TodoID  uuid.UUID
	SelectedBy  string
	Position    int32
	Reason      *string
	AgentNoteID *int64
}
