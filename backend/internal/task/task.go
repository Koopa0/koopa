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
	ID            uuid.UUID  `json:"id"`
	Title         string     `json:"title"`
	Status        Status     `json:"status"`
	Due           *time.Time `json:"due,omitempty"`
	ProjectID     *uuid.UUID `json:"project_id,omitempty"`
	NotionPageID  *string    `json:"notion_page_id,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	Energy        string     `json:"energy,omitempty"`
	Priority      string     `json:"priority,omitempty"`
	RecurInterval *int32     `json:"recur_interval,omitempty"`
	RecurUnit     string     `json:"recur_unit,omitempty"`
	MyDay         bool       `json:"my_day"`
	Description   string     `json:"description,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// IsRecurring reports whether the task has a recurrence schedule.
func (t Task) IsRecurring() bool {
	return t.RecurInterval != nil && *t.RecurInterval > 0
}

// NextDue calculates the next due date based on recurrence settings.
// Returns nil if the task is not recurring or has no due date.
func (t Task) NextDue() *time.Time {
	if !t.IsRecurring() || t.Due == nil {
		return nil
	}
	base := *t.Due
	interval := int(*t.RecurInterval)
	var next time.Time
	switch t.RecurUnit {
	case "Day(s)":
		next = base.AddDate(0, 0, interval)
	case "Week(s)":
		next = base.AddDate(0, 0, interval*7)
	case "Month(s)":
		next = base.AddDate(0, interval, 0)
	case "Year(s)":
		next = base.AddDate(interval, 0, 0)
	default:
		// unknown unit, assume days
		next = base.AddDate(0, 0, interval)
	}
	return &next
}

// PendingTaskDetail represents a pending task with project context for MCP tools.
type PendingTaskDetail struct {
	ID            uuid.UUID  `json:"id"`
	Title         string     `json:"title"`
	Status        Status     `json:"status"`
	Due           *time.Time `json:"due,omitempty"`
	ProjectTitle  string     `json:"project_title"`
	ProjectSlug   string     `json:"project_slug"`
	Energy        string     `json:"energy,omitempty"`
	Priority      string     `json:"priority,omitempty"`
	RecurInterval *int32     `json:"recur_interval,omitempty"`
	RecurUnit     string     `json:"recur_unit,omitempty"`
	MyDay         bool       `json:"my_day"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// DailySummaryHint holds computed task counts for metrics (replaces manual counting).
type DailySummaryHint struct {
	MyDayTasksTotal     int      `json:"my_day_tasks_total"`
	MyDayTasksCompleted int      `json:"my_day_tasks_completed"`
	NonMyDayCompleted   int      `json:"non_my_day_completed"`
	TotalCompleted      int      `json:"total_completed"`
	CompletedTitles     []string `json:"completed_titles"`
}

// UpsertByNotionParams are the parameters for upserting a task from Notion.
// CompletedAt is managed by the DB: set on first transition to done, preserved thereafter.
type UpsertByNotionParams struct {
	Title         string
	Status        Status
	Due           *time.Time
	ProjectID     *uuid.UUID
	NotionPageID  string
	Energy        string
	Priority      string
	RecurInterval *int32
	RecurUnit     string
	MyDay         bool
	Description   string
}
