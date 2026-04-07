// Package task provides task tracking with GTD-informed lifecycle.
package task

import (
	"context"
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
	StatusInbox      Status = "inbox"
	StatusTodo       Status = "todo"
	StatusInProgress Status = "in-progress"
	StatusDone       Status = "done"
	StatusSomeday    Status = "someday"
)

// Task represents a task with GTD lifecycle.
type Task struct {
	ID            uuid.UUID  `json:"id"`
	Title         string     `json:"title"`
	Status        Status     `json:"status"`
	Due           *time.Time `json:"due,omitempty"`
	ProjectID     *uuid.UUID `json:"project_id,omitempty"`
	NotionPageID  *string    `json:"notion_page_id,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	Energy        *string    `json:"energy,omitempty"`
	Priority      *string    `json:"priority,omitempty"`
	RecurInterval *int32     `json:"recur_interval,omitempty"`
	RecurUnit     *string    `json:"recur_unit,omitempty"`
	Description   string     `json:"description,omitempty"`
	Assignee      string     `json:"assignee"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// RecurringDoneHandler is called when a recurring task is completed.
type RecurringDoneHandler func(ctx context.Context, t *Task) error

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
	next := advanceDate(*t.Due, int(*t.RecurInterval), derefStr(t.RecurUnit))
	return &next
}

// NextCycleDateOnOrAfter returns the first recurrence date on or after cutoff.
func (t *Task) NextCycleDateOnOrAfter(cutoff time.Time) *time.Time {
	if !t.IsRecurring() || t.Due == nil {
		return nil
	}
	base := *t.Due
	interval := int(*t.RecurInterval)
	unit := derefStr(t.RecurUnit)
	cutoffDate := truncateToDate(cutoff)
	baseDate := truncateToDate(base)

	if !baseDate.Before(cutoffDate) {
		return &baseDate
	}

	switch unit {
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
			cur = advanceDate(cur, interval, unit)
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
		cur = advanceDate(cur, int(*t.RecurInterval), derefStr(t.RecurUnit))
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

func derefStr(p *string) string {
	if p != nil {
		return *p
	}
	return ""
}

// PendingTask represents a task pending completion (lightweight).
type PendingTask struct {
	Title string
	Due   string
}

// ProjectCompletion holds a per-project completion count.
type ProjectCompletion struct {
	ProjectTitle string
	Completed    int64
}

// PendingTaskDetail represents a pending task with project context.
type PendingTaskDetail struct {
	ID            uuid.UUID  `json:"id"`
	Title         string     `json:"title"`
	Status        Status     `json:"status"`
	Due           *time.Time `json:"due,omitempty"`
	ProjectTitle  string     `json:"project_title"`
	ProjectSlug   string     `json:"project_slug"`
	Energy        *string    `json:"energy,omitempty"`
	Priority      *string    `json:"priority,omitempty"`
	RecurInterval *int32     `json:"recur_interval,omitempty"`
	RecurUnit     *string    `json:"recur_unit,omitempty"`
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
	Energy        *string    `json:"energy,omitempty"`
	Priority      *string    `json:"priority,omitempty"`
	RecurInterval *int32     `json:"recur_interval,omitempty"`
	RecurUnit     *string    `json:"recur_unit,omitempty"`
	Assignee      string     `json:"assignee"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	Description   string     `json:"description,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
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

// ValidAssignee reports whether a is a known assignee value.
func ValidAssignee(a string) bool {
	switch a {
	case "human", "claude-code", "cowork":
		return true
	}
	return false
}
