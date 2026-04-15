// Package todo provides personal GTD work-item tracking.
//
// Named todo (not task) to free the bare word "task" for the inter-agent
// coordination entity in internal/task/. Vocabulary discipline from the
// coordination rebuild: task = agent-to-agent work unit, todo = personal GTD item.
// See docs/architecture/coordination-layer-target.md §3.
package todo

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound indicates the todo item does not exist.
var ErrNotFound = errors.New("todo: not found")

// State represents a todo item's GTD lifecycle state. Mirrors the todo_state
// SQL enum. Underscore values (in_progress) replace the previous hyphenated
// form (in-progress) per naming consistency in the coordination rebuild.
type State string

const (
	StateInbox      State = "inbox"
	StateTodo       State = "todo"
	StateInProgress State = "in_progress"
	StateDone       State = "done"
	StateSomeday    State = "someday"
)

// Item represents a personal GTD work item.
//
// Unqualified "Item" reads cleanly at the call site (todo.Item) and avoids
// the pkg.PkgSomething stutter that naming.md forbids.
type Item struct {
	ID               uuid.UUID  `json:"id"`
	Title            string     `json:"title"`
	State            State      `json:"state"`
	Due              *time.Time `json:"due,omitempty"`
	ProjectID        *uuid.UUID `json:"project_id,omitempty"`
	ExternalProvider *string    `json:"external_provider,omitempty"`
	ExternalRef      *string    `json:"external_ref,omitempty"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	Energy           *string    `json:"energy,omitempty"`
	Priority         *string    `json:"priority,omitempty"`
	RecurInterval    *int32     `json:"recur_interval,omitempty"`
	RecurUnit        *string    `json:"recur_unit,omitempty"`
	Description      string     `json:"description,omitempty"`
	Assignee         string     `json:"assignee"`
	CreatedBy        string     `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// RecurringDoneHandler is called when a recurring todo item is completed.
type RecurringDoneHandler func(ctx context.Context, t *Item) error

// IsRecurring reports whether the item has a recurrence schedule.
func (t *Item) IsRecurring() bool {
	return t.RecurInterval != nil && *t.RecurInterval > 0
}

// NextDue calculates the next due date based on recurrence settings.
// Returns nil if the item is not recurring or has no due date.
// For months, clamps to the last day of the target month to prevent drift
// (e.g., Jan 31 + 1 month = Feb 28, not Mar 3).
func (t *Item) NextDue() *time.Time {
	if !t.IsRecurring() || t.Due == nil {
		return nil
	}
	next := advanceDate(*t.Due, int(*t.RecurInterval), derefStr(t.RecurUnit))
	return &next
}

// NextCycleDateOnOrAfter returns the first recurrence date on or after cutoff.
func (t *Item) NextCycleDateOnOrAfter(cutoff time.Time) *time.Time {
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
		cycles := (days + interval - 1) / interval
		next := baseDate.AddDate(0, 0, cycles*interval)
		return &next
	case "weeks":
		days := daysBetween(baseDate, cutoffDate)
		stepDays := interval * 7
		cycles := (days + stepDays - 1) / stepDays
		next := baseDate.AddDate(0, 0, cycles*stepDays)
		return &next
	default:
		cur := baseDate
		for cur.Before(cutoffDate) {
			cur = advanceDate(cur, interval, unit)
		}
		return &cur
	}
}

// MissedOccurrences returns all occurrence dates between the current due and cutoff (exclusive).
func (t *Item) MissedOccurrences(cutoff time.Time) []time.Time {
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

func addMonthsClamped(base time.Time, months int) time.Time {
	y, m, d := base.Date()
	targetMonth := time.Month(int(m) + months)
	lastDay := time.Date(y, targetMonth+1, 0, 0, 0, 0, 0, base.Location()).Day()
	if d > lastDay {
		d = lastDay
	}
	return time.Date(y, targetMonth, d, 0, 0, 0, 0, base.Location())
}

func truncateToDate(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

func daysBetween(a, b time.Time) int {
	return int(b.Sub(a).Hours() / 24)
}

func derefStr(p *string) string {
	if p != nil {
		return *p
	}
	return ""
}

// Pending is a lightweight projection used by morning_context.
type Pending struct {
	Title string
	Due   string
}

// ProjectCompletion holds a per-project completion count.
type ProjectCompletion struct {
	ProjectTitle string
	Completed    int64
}

// PendingDetail is a pending todo with project context.
type PendingDetail struct {
	ID            uuid.UUID  `json:"id"`
	Title         string     `json:"title"`
	State         State      `json:"state"`
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

// SearchDetail is a search hit with project context.
type SearchDetail struct {
	ID            uuid.UUID  `json:"id"`
	Title         string     `json:"title"`
	State         State      `json:"state"`
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

// CompletedDetail is a recently completed todo with project context.
type CompletedDetail struct {
	ID           uuid.UUID  `json:"id"`
	Title        string     `json:"title"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	ProjectTitle string     `json:"project_title"`
}

// CreatedDetail is a recently created todo with project context.
type CreatedDetail struct {
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
