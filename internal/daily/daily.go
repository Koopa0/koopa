// Copyright 2026 Koopa. All rights reserved.

// Package daily provides daily plan item storage.
//
// Daily plan items represent todo items committed to a specific day's plan.
// They are the source of truth for "what was planned today" — distinct
// from todo_items themselves (which track GTD lifecycle).
package daily

import (
	"errors"
	"time"

	"github.com/Koopa0/koopa/internal/todo"
	"github.com/google/uuid"
)

// ErrItemResolved indicates a daily plan item for the date already reached a
// terminal state (done, deferred, or dropped) and so cannot be re-planned.
var ErrItemResolved = errors.New("dailyplan: item already resolved for date")

// Status represents a daily plan item's lifecycle state.
type Status string

const (
	StatusPlanned  Status = "planned"
	StatusDone     Status = "done"
	StatusDeferred Status = "deferred"
	StatusDropped  Status = "dropped"
)

// RemovedItem describes a daily plan item that DeletePlannedByDate
// removed during re-planning. It carries just enough context (todo_id
// + title) for plan_day callers to surface "what got displaced" without
// re-querying the todos table.
type RemovedItem struct {
	ID        uuid.UUID `json:"id"`
	TodoID    uuid.UUID `json:"todo_id"`
	TodoTitle string    `json:"todo_title"`
}

// Item represents a daily plan item with joined todo item details.
type Item struct {
	ID           uuid.UUID  `json:"id"`
	PlanDate     time.Time  `json:"plan_date"`
	TodoID       uuid.UUID  `json:"todo_id"`
	SelectedBy   string     `json:"selected_by"`
	Position     int32      `json:"position"`
	Reason       *string    `json:"reason,omitempty"`
	Status       Status     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	TodoTitle    string     `json:"todo_title"`
	TodoState    string     `json:"todo_state"`
	TodoDue      *time.Time `json:"todo_due,omitempty"`
	TodoEnergy   *string    `json:"todo_energy,omitempty"`
	TodoPriority *string    `json:"todo_priority,omitempty"`
	// Recurrence + last completion of the backing todo, carried so completion
	// counting can recognise a recurring occurrence completed today (which never
	// sets todo_state=done). See IsCompletedOn.
	TodoRecurWeekdays   *int16     `json:"todo_recur_weekdays,omitempty"`
	TodoRecurInterval   *int32     `json:"todo_recur_interval,omitempty"`
	TodoLastCompletedOn *time.Time `json:"todo_last_completed_on,omitempty"`
	ProjectTitle        string     `json:"project_title"`
	ProjectSlug         string     `json:"project_slug"`
}

// IsCompletedOn reports whether this planned todo counts as completed for the
// given plan date — the single source both the Today aggregate and
// brief(reflection) use, so the two surfaces can never disagree on completion.
// A todo counts as done when it reached the terminal done state, OR when it is
// a recurring todo whose occurrence was completed on that date (last_completed_on
// stamped == date). Recurring completions never set todo_state=done, so without
// the recurrence arm a routine done today would be miscounted as still pending.
func (i *Item) IsCompletedOn(date time.Time) bool {
	if i.TodoState == string(todo.StateDone) {
		return true
	}
	recurring := i.TodoRecurWeekdays != nil || i.TodoRecurInterval != nil
	if recurring && i.TodoLastCompletedOn != nil {
		return sameCivilDate(*i.TodoLastCompletedOn, date)
	}
	return false
}

// IsDeferred reports whether the backing todo was deferred (someday). Pairs with
// IsCompletedOn for the planned/completed/deferred split.
func (i *Item) IsDeferred() bool {
	return i.TodoState == string(todo.StateSomeday)
}

// sameCivilDate compares the calendar date (year/month/day) of two times in
// their own locations. last_completed_on is a DATE (read as midnight UTC) while
// the plan date is the owner's timezone midnight; comparing the date components
// is the timezone-correct civil-date equality, not an instant comparison.
func sameCivilDate(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

// CreateItemParams holds the parameters for creating a daily plan item.
type CreateItemParams struct {
	PlanDate   time.Time
	TodoID     uuid.UUID
	SelectedBy string
	Position   int32
	Reason     *string
}
