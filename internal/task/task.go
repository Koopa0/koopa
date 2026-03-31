// Package task provides task tracking synced from Notion.
package task

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrNotFound indicates the task does not exist.
	ErrNotFound = errors.New("task: not found")
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
	Assignee      string     `json:"assignee"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// IsRecurring reports whether the task has a recurrence schedule.
func (t *Task) IsRecurring() bool {
	return t.RecurInterval != nil && *t.RecurInterval > 0
}

// NextDue calculates the next due date based on recurrence settings.
// Returns nil if the task is not recurring or has no due date.
// For months, clamps to the last day of the target month to prevent drift
// (e.g., Jan 31 + 1 month = Feb 28, not Mar 3).
func (t *Task) NextDue() *time.Time {
	if !t.IsRecurring() || t.Due == nil {
		return nil
	}
	next := advanceDate(*t.Due, int(*t.RecurInterval), t.RecurUnit)
	return &next
}

// NextCycleDateOnOrAfter returns the first recurrence date on or after cutoff.
// For days/weeks, this is calculated mathematically.
// For months/years, this loops with clamped month arithmetic.
// Returns nil if the task is not recurring or has no due date.
func (t *Task) NextCycleDateOnOrAfter(cutoff time.Time) *time.Time {
	if !t.IsRecurring() || t.Due == nil {
		return nil
	}
	base := *t.Due
	interval := int(*t.RecurInterval)
	cutoffDate := truncateToDate(cutoff)
	baseDate := truncateToDate(base)

	if !baseDate.Before(cutoffDate) {
		return &baseDate
	}

	switch t.RecurUnit {
	case "days":
		days := daysBetween(baseDate, cutoffDate)
		cycles := (days + interval - 1) / interval // ceil division
		next := baseDate.AddDate(0, 0, cycles*interval)
		return &next
	case "weeks":
		days := daysBetween(baseDate, cutoffDate)
		stepDays := interval * 7
		cycles := (days + stepDays - 1) / stepDays
		next := baseDate.AddDate(0, 0, cycles*stepDays)
		return &next
	default:
		// months, years, or unknown: loop with clamped arithmetic
		cur := baseDate
		for cur.Before(cutoffDate) {
			cur = advanceDate(cur, interval, t.RecurUnit)
		}
		return &cur
	}
}

// MissedOccurrences returns all occurrence dates between the current due and cutoff (exclusive).
// Each returned date represents one missed recurrence cycle.
func (t *Task) MissedOccurrences(cutoff time.Time) []time.Time {
	if !t.IsRecurring() || t.Due == nil {
		return nil
	}
	cutoffDate := truncateToDate(cutoff)
	cur := truncateToDate(*t.Due)
	var missed []time.Time
	for cur.Before(cutoffDate) {
		missed = append(missed, cur)
		cur = advanceDate(cur, int(*t.RecurInterval), t.RecurUnit)
	}
	return missed
}

// advanceDate moves a date forward by interval units, clamping months to avoid drift.
func advanceDate(base time.Time, interval int, unit string) time.Time {
	switch unit {
	case "days":
		return base.AddDate(0, 0, interval)
	case "weeks":
		return base.AddDate(0, 0, interval*7)
	case "months":
		return addMonthsClamped(base, interval)
	case "years":
		return addMonthsClamped(base, interval*12)
	default:
		return base.AddDate(0, 0, interval)
	}
}

// addMonthsClamped adds months to a date, clamping the day to the last day of
// the target month. This prevents Jan 31 + 1 month from becoming Mar 3.
func addMonthsClamped(base time.Time, months int) time.Time {
	y, m, d := base.Date()
	targetMonth := time.Month(int(m) + months)
	// last day of target month: day 0 of the following month
	lastDay := time.Date(y, targetMonth+1, 0, 0, 0, 0, 0, base.Location()).Day()
	if d > lastDay {
		d = lastDay
	}
	return time.Date(y, targetMonth, d, 0, 0, 0, 0, base.Location())
}

// truncateToDate strips the time component, keeping only year/month/day.
func truncateToDate(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

// daysBetween returns the number of days between a and b (b - a).
func daysBetween(a, b time.Time) int {
	return int(b.Sub(a).Hours() / 24)
}

// PendingTask represents a task pending completion.
// Used by ai/report flows for lightweight task summaries.
type PendingTask struct {
	Title string
	Due   string // YYYY-MM-DD or empty
}

// ProjectCompletion holds a per-project completion count.
// Used by ai/report flows for weekly review summaries.
type ProjectCompletion struct {
	ProjectTitle string
	Completed    int64
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
	Assignee      string     `json:"assignee"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// SearchTaskDetail represents a task search result with project context.
type SearchTaskDetail struct {
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
	Assignee      string     `json:"assignee"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	Description   string     `json:"description,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// MyDaySnapshot represents a task in the My Day list for response enrichment.
type MyDaySnapshot struct {
	ID           uuid.UUID `json:"id"`
	Title        string    `json:"title"`
	ProjectTitle string    `json:"project_title"`
	Energy       string    `json:"energy,omitempty"`
	Priority     string    `json:"priority,omitempty"`
	Assignee     string    `json:"assignee"`
}

// ValidAssignee reports whether a is a known assignee value.
func ValidAssignee(a string) bool {
	switch a {
	case "human", "claude-code", "cowork":
		return true
	}
	return false
}

// DailySummaryHint holds computed task counts for metrics (replaces manual counting).
type DailySummaryHint struct {
	MyDayTasksTotal     int      `json:"my_day_tasks_total"`
	MyDayTasksCompleted int      `json:"my_day_tasks_completed"`
	NonMyDayCompleted   int      `json:"non_my_day_completed"`
	TotalCompleted      int      `json:"total_completed"`
	CompletedTitles     []string `json:"completed_titles"`
}

// CompletedTaskDetail represents a completed task with project context.
type CompletedTaskDetail struct {
	ID           uuid.UUID  `json:"id"`
	Title        string     `json:"title"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	ProjectTitle string     `json:"project_title"`
}

// CreatedTaskDetail represents a recently created task with project context.
type CreatedTaskDetail struct {
	ID           uuid.UUID `json:"id"`
	Title        string    `json:"title"`
	CreatedAt    time.Time `json:"created_at"`
	ProjectTitle string    `json:"project_title"`
}

// MyDayNotionTask holds the minimal fields needed for Notion My Day sync.
type MyDayNotionTask struct {
	ID           uuid.UUID
	NotionPageID string
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
	Assignee      string
}
