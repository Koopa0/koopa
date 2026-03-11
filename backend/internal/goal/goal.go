// Package goal provides goal tracking synced from Notion.
package goal

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status represents a goal's lifecycle status.
type Status string

const (
	StatusNotStarted Status = "not-started"
	StatusInProgress Status = "in-progress"
	StatusDone       Status = "done"
	StatusAbandoned  Status = "abandoned"
)

// Goal represents a personal goal synced from Notion.
type Goal struct {
	ID           uuid.UUID  `json:"id"`
	Title        string     `json:"title"`
	Description  string     `json:"description"`
	Status       Status     `json:"status"`
	Area         string     `json:"area"`
	Quarter      string     `json:"quarter"`
	Deadline     *time.Time `json:"deadline,omitempty"`
	NotionPageID *string    `json:"notion_page_id,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// UpsertByNotionParams are the parameters for upserting a goal from Notion.
type UpsertByNotionParams struct {
	Title        string
	Description  string
	Status       Status
	Area         string
	Quarter      string
	Deadline     *time.Time
	NotionPageID string
}

var (
	// ErrNotFound indicates the goal does not exist.
	ErrNotFound = errors.New("not found")
)
