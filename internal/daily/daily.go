// Package daily provides daily plan item storage.
//
// Daily plan items represent tasks committed to a specific day's plan.
// They are the source of truth for "what was planned today" — distinct
// from tasks themselves (which track work lifecycle).
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

// Item represents a daily plan item with joined task details.
type Item struct {
	ID           uuid.UUID  `json:"id"`
	PlanDate     time.Time  `json:"plan_date"`
	TaskID       uuid.UUID  `json:"task_id"`
	SelectedBy   string     `json:"selected_by"`
	Position     int32      `json:"position"`
	Reason       *string    `json:"reason,omitempty"`
	JournalID    *int64     `json:"journal_id,omitempty"`
	Status       Status     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	TaskTitle    string     `json:"task_title"`
	TaskStatus   string     `json:"task_status"`
	TaskDue      *time.Time `json:"task_due,omitempty"`
	TaskEnergy   *string    `json:"task_energy,omitempty"`
	TaskPriority *string    `json:"task_priority,omitempty"`
	TaskAssignee string     `json:"task_assignee"`
	ProjectTitle string     `json:"project_title"`
	ProjectSlug  string     `json:"project_slug"`
}

// CreateItemParams holds the parameters for creating a daily plan item.
type CreateItemParams struct {
	PlanDate   time.Time
	TaskID     uuid.UUID
	SelectedBy string
	Position   int32
	Reason     *string
	JournalID  *int64
}
