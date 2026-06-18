// Copyright 2026 Koopa. All rights reserved.

// Package goal provides goal and milestone tracking for the admin
// planning surface. A goal is a long-horizon outcome — optionally tied
// to an area, quarter, or deadline — whose status moves through
// not_started → in_progress → done | abandoned | on_hold; milestones
// are a goal's checkable progress markers.
package goal

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status represents a goal's lifecycle status.
type Status string

const (
	// StatusProposed indicates an agent-proposed inert draft awaiting owner
	// triage. A proposed goal feeds no list, alignment, or brief; the owner
	// activates it (→ not_started) or rejects it (hard DELETE) in admin.
	StatusProposed Status = "proposed"

	// StatusNotStarted indicates the goal has not been started.
	StatusNotStarted Status = "not_started"

	// StatusInProgress indicates the goal is actively being worked on.
	StatusInProgress Status = "in_progress"

	// StatusDone indicates the goal has been achieved.
	StatusDone Status = "done"

	// StatusAbandoned indicates the goal was abandoned.
	StatusAbandoned Status = "abandoned"

	// StatusOnHold indicates the goal is paused without abandonment.
	StatusOnHold Status = "on_hold"
)

// Goal represents a personal goal.
type Goal struct {
	ID          uuid.UUID  `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Status      Status     `json:"status"`
	AreaID      *uuid.UUID `json:"area_id,omitempty"`
	Quarter     *string    `json:"quarter,omitempty"`
	Deadline    *time.Time `json:"deadline,omitempty"`
	CreatedBy   *string    `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

var (
	// ErrNotFound indicates the goal does not exist.
	ErrNotFound = errors.New("goal: not found")
	// ErrConflict indicates a uniqueness violation.
	ErrConflict = errors.New("goal: conflict")
	// ErrInvalidInput signals a client-supplied value the database rejected:
	// a foreign key pointing at a non-existent area_id (goal) or goal_id
	// (milestone).
	ErrInvalidInput = errors.New("goal: invalid input")
	// ErrNotProposed indicates an activate/reject targeted a goal or area
	// that exists but is not in status=proposed. Real planning rows are not
	// activated or hard-deleted through the proposal-triage path.
	ErrNotProposed = errors.New("goal: not proposed")
)

// containsControlChars reports whether s contains any control character.
func containsControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}
