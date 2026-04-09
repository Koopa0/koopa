// Package plan provides learning plan management — ordered, mutable curricula
// that track which learning items to practice and in what order.
package plan

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrNotFound indicates the requested plan or plan item does not exist.
	ErrNotFound = errors.New("plan: not found")
	// ErrConflict indicates a uniqueness or state conflict.
	ErrConflict = errors.New("plan: conflict")
)

// Status represents a plan lifecycle state.
type Status string

// Plan lifecycle statuses: draft → active → completed/paused/abandoned.
const (
	StatusDraft     Status = "draft"
	StatusActive    Status = "active"
	StatusCompleted Status = "completed"
	StatusPaused    Status = "paused"
	StatusAbandoned Status = "abandoned"
)

// ItemStatus represents a plan item lifecycle state.
type ItemStatus string

// Plan item statuses: planned → completed/skipped/substituted.
const (
	ItemPlanned     ItemStatus = "planned"
	ItemCompleted   ItemStatus = "completed"
	ItemSkipped     ItemStatus = "skipped"
	ItemSubstituted ItemStatus = "substituted"
)

// Plan represents an ordered learning curriculum.
type Plan struct {
	ID          uuid.UUID       `json:"id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Domain      string          `json:"domain"`
	GoalID      *uuid.UUID      `json:"goal_id,omitempty"`
	Status      Status          `json:"status"`
	TargetCount *int32          `json:"target_count,omitempty"`
	PlanConfig  json.RawMessage `json:"plan_config"`
	CreatedBy   string          `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// PlanItem represents a single entry in a learning plan's ordered sequence.
type PlanItem struct {
	ID                   uuid.UUID  `json:"id"`
	PlanID               uuid.UUID  `json:"plan_id"`
	LearningItemID       uuid.UUID  `json:"learning_item_id"`
	Position             int32      `json:"position"`
	Status               ItemStatus `json:"status"`
	Phase                *string    `json:"phase,omitempty"`
	SubstitutedBy        *uuid.UUID `json:"substituted_by,omitempty"`
	CompletedByAttemptID *uuid.UUID `json:"completed_by_attempt_id,omitempty"`
	Reason               *string    `json:"reason,omitempty"`
	AddedAt              time.Time  `json:"added_at"`
	CompletedAt          *time.Time `json:"completed_at,omitempty"`
}

// PlanItemWithTitle extends PlanItem with the parent plan's title,
// used when querying plan items by learning item.
type PlanItemWithTitle struct {
	PlanItem
	PlanTitle string `json:"plan_title"`
}

// PlanItemDetail is the plan-item projection returned by manage_plan(progress).
// It is flat (no embedded PlanItem) so the JSON field name for the plan-item
// primary key is explicitly `plan_item_id` — the exact identifier callers pass
// back in update_item. Embedding PlanItem would serialize its ID as "id" and
// create ambiguity with LearningItemID.
type PlanItemDetail struct {
	PlanItemID           uuid.UUID  `json:"plan_item_id"`
	PlanID               uuid.UUID  `json:"plan_id"`
	LearningItemID       uuid.UUID  `json:"learning_item_id"`
	Position             int32      `json:"position"`
	Status               ItemStatus `json:"status"`
	Phase                *string    `json:"phase,omitempty"`
	SubstitutedBy        *uuid.UUID `json:"substituted_by,omitempty"`
	CompletedByAttemptID *uuid.UUID `json:"completed_by_attempt_id,omitempty"`
	Reason               *string    `json:"reason,omitempty"`
	AddedAt              time.Time  `json:"added_at"`
	CompletedAt          *time.Time `json:"completed_at,omitempty"`

	ItemTitle      string  `json:"item_title"`
	ItemDomain     string  `json:"item_domain"`
	ItemDifficulty *string `json:"item_difficulty,omitempty"`
	ItemExternalID *string `json:"item_external_id,omitempty"`
}

// Progress summarises a plan's item completion counts.
type Progress struct {
	Total       int32 `json:"total"`
	Completed   int32 `json:"completed"`
	Skipped     int32 `json:"skipped"`
	Substituted int32 `json:"substituted"`
	Remaining   int32 `json:"remaining"`
}

var phaseRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// ValidatePhase checks that a phase label follows kebab-case convention
// (lowercase alphanumeric segments separated by hyphens, e.g. "1-arrays", "phase-2-trees").
// It returns a non-nil error if phase is empty, contains uppercase, spaces, underscores, or consecutive hyphens.
func ValidatePhase(phase string) error {
	if !phaseRe.MatchString(phase) {
		return fmt.Errorf("invalid phase %q: must be kebab-case (e.g. 1-arrays, phase-2-trees)", phase)
	}
	return nil
}
