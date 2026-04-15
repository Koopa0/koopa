// Package hypothesis provides falsifiable hypothesis tracking.
//
// Renamed from "insight" in the coordination rebuild because the entity
// already had a hypothesis column and an invalidation_condition column —
// "insight" was a vague label; "hypothesis" is precise. The lifecycle is
// unverified → verified | invalidated → archived.
//
// See docs/architecture/coordination-layer-target.md §3.
package hypothesis

import (
	"encoding/json"
	"errors"
	"time"
)

// ErrNotFound indicates the hypothesis does not exist.
var ErrNotFound = errors.New("hypothesis: not found")

// State mirrors the hypothesis_state SQL enum.
type State string

const (
	StateUnverified  State = "unverified"
	StateVerified    State = "verified"
	StateInvalidated State = "invalidated"
	StateArchived    State = "archived"
)

// Record is a tracked hypothesis with accumulating evidence.
//
// Unqualified "Record" avoids the hypothesis.Hypothesis stutter. "Record"
// reads as "a recorded claim with supporting data" which matches the
// entity's lifecycle (unverified → verified/invalidated → archived).
type Record struct {
	ID                    int64          `json:"id"`
	Author                string         `json:"author"`
	Content               string         `json:"content"`
	State                 State          `json:"state"`
	Claim                 string         `json:"claim"`
	InvalidationCondition string         `json:"invalidation_condition"`
	Metadata              map[string]any `json:"metadata,omitempty"`
	ObservedDate          time.Time      `json:"observed_date"`
	CreatedAt             time.Time      `json:"created_at"`
}

// CreateParams holds parameters for creating a hypothesis record.
type CreateParams struct {
	Author                string
	Content               string
	Claim                 string
	InvalidationCondition string
	Metadata              json.RawMessage
	ObservedDate          time.Time
}
