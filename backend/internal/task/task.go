// Package task provides task tracking synced from Notion.
package task

import (
	"time"

	"github.com/google/uuid"
)

// Status represents a task's lifecycle status.
type Status string

const (
	StatusTodo       Status = "todo"
	StatusInProgress Status = "in-progress"
	StatusDone       Status = "done"
)

// Task represents a task synced from Notion.
type Task struct {
	ID           uuid.UUID  `json:"id"`
	Title        string     `json:"title"`
	Status       Status     `json:"status"`
	Due          *time.Time `json:"due,omitempty"`
	ProjectID    *uuid.UUID `json:"project_id,omitempty"`
	NotionPageID *string    `json:"notion_page_id,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// PendingTaskDetail represents a pending task with project context for MCP tools.
type PendingTaskDetail struct {
	ID           uuid.UUID  `json:"id"`
	Title        string     `json:"title"`
	Status       Status     `json:"status"`
	Due          *time.Time `json:"due,omitempty"`
	ProjectTitle string     `json:"project_title"`
	ProjectSlug  string     `json:"project_slug"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// UpsertByNotionParams are the parameters for upserting a task from Notion.
// CompletedAt is managed by the DB: set on first transition to done, preserved thereafter.
type UpsertByNotionParams struct {
	Title        string
	Status       Status
	Due          *time.Time
	ProjectID    *uuid.UUID
	NotionPageID string
}
