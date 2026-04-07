// Package goal provides goal tracking.
package goal

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status represents a goal's lifecycle status.
type Status string

const (
	// StatusNotStarted indicates the goal has not been started.
	StatusNotStarted Status = "not-started"

	// StatusInProgress indicates the goal is actively being worked on.
	StatusInProgress Status = "in-progress"

	// StatusDone indicates the goal has been achieved.
	StatusDone Status = "done"

	// StatusAbandoned indicates the goal was abandoned.
	StatusAbandoned Status = "abandoned"
)

// Goal represents a personal goal.
type Goal struct {
	ID           uuid.UUID  `json:"id"`
	Title        string     `json:"title"`
	Description  string     `json:"description"`
	Status       Status     `json:"status"`
	AreaID       *uuid.UUID `json:"area_id,omitempty"`
	Quarter      *string    `json:"quarter,omitempty"`
	Deadline     *time.Time `json:"deadline,omitempty"`
	NotionPageID *string    `json:"notion_page_id,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

var (
	// ErrNotFound indicates the goal does not exist.
	ErrNotFound = errors.New("goal: not found")
)
