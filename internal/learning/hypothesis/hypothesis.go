// Copyright 2026 Koopa. All rights reserved.

// Package hypothesis provides falsifiable hypothesis tracking.
//
// A hypothesis carries a one-line claim plus the invalidation condition
// that would disprove it. Evidence accumulates in metadata until the state
// transitions to verified or invalidated. Lifecycle:
// draft → unverified → verified | invalidated → archived.
//
// draft is the agent-created pre-endorsement state (MCP v3.1 inert drafts):
// inert by definition — excluded from brief(morning), the Today aggregate,
// and every dashboard; visible only in the admin hypotheses list. A draft
// leaves draft only via owner endorsement (Endorse, draft → unverified) or
// draft-only deletion (DeleteDraft). Admin-created hypotheses land directly
// in unverified — creating in admin IS the endorsement.
package hypothesis

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Sentinel errors.
var (
	// ErrNotFound indicates the hypothesis does not exist.
	ErrNotFound = errors.New("hypothesis: not found")

	// ErrEvidenceRequired indicates a resolution attempt did not
	// supply any evidence source. Callers must provide at least one
	// of attempt_id, observation_id, or a non-blank resolution summary
	// before transitioning to verified or invalidated.
	ErrEvidenceRequired = errors.New("hypothesis: evidence required to resolve")

	// ErrEvidenceNotFound indicates a referenced attempt or observation
	// does not exist in the database. Surfaces the FK violation from
	// chk_hypothesis_resolution without leaking internal DB detail.
	ErrEvidenceNotFound = errors.New("hypothesis: referenced attempt or observation not found")

	// ErrInvalidTransition indicates a state transition that cannot be
	// satisfied by the method the caller chose. Two triggers:
	//
	//   - UpdateState was called with verified or invalidated. Those
	//     terminal states require evidence + resolved_at and MUST go
	//     through UpdateResolution. Rejecting at the Go layer converts
	//     a would-be opaque 23514 into a named, handler-mappable error.
	//
	//   - UpdateResolution failed chk_hypothesis_resolved_at, meaning the
	//     (state, resolved_at) pair is inconsistent (e.g. resolving to
	//     unverified/archived while writing a non-NULL resolved_at, which
	//     should be structurally impossible but maps here if it ever
	//     fires instead of silently becoming ErrEvidenceRequired).
	//
	//   - UpdateState was called with draft as the target. Nothing
	//     transitions TO draft — it is exclusively an initial state set
	//     at creation time; demoting an endorsed row back to draft would
	//     silently un-endorse it.
	//
	//   - Create was called with an initial state other than draft or
	//     unverified. verified/invalidated/archived rows cannot be born —
	//     they exist only as the outcome of a lifecycle transition.
	ErrInvalidTransition = errors.New("hypothesis: invalid state transition")

	// ErrNotDraft indicates Endorse or DeleteDraft targeted a row whose
	// state is not draft. Endorsement applies only to agent drafts, and
	// non-draft rows are permanent records that must never be deleted.
	ErrNotDraft = errors.New("hypothesis: not a draft")
)

// State mirrors the hypothesis_state SQL enum.
type State string

const (
	StateDraft       State = "draft"
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
	ID                      uuid.UUID      `json:"id"`
	CreatedBy               string         `json:"created_by"`
	Content                 string         `json:"content"`
	State                   State          `json:"state"`
	Claim                   string         `json:"claim"`
	InvalidationCondition   string         `json:"invalidation_condition"`
	Metadata                map[string]any `json:"metadata,omitempty"`
	ObservedDate            time.Time      `json:"observed_date"`
	ResolvedAt              *time.Time     `json:"resolved_at,omitempty"`
	ResolvedByAttemptID     *uuid.UUID     `json:"resolved_by_attempt_id,omitempty"`
	ResolvedByObservationID *uuid.UUID     `json:"resolved_by_observation_id,omitempty"`
	ResolutionSummary       *string        `json:"resolution_summary,omitempty"`
	CreatedAt               time.Time      `json:"created_at"`
}

// CreateParams holds parameters for creating a hypothesis record.
type CreateParams struct {
	CreatedBy             string
	Content               string
	Claim                 string
	InvalidationCondition string
	Metadata              json.RawMessage
	ObservedDate          time.Time

	// State is the initial lifecycle state. Zero value defaults to
	// StateUnverified (the admin create path — creating in admin IS the
	// endorsement). StateDraft is the agent path (MCP draft_hypothesis).
	// Any other value is rejected with ErrInvalidTransition: resolved
	// states exist only as transition outcomes, never at birth.
	State State
}

// ResolveParams carries the evidence sources that accompany a transition
// to verified or invalidated. The handler is responsible for enforcing
// the "at least one source" rule before calling the store; the schema
// CHECK (chk_hypothesis_resolution) is a last-resort safety net.
//
// An empty Summary is treated as "not supplied" by the store — it will
// be written as NULL, not as "".
type ResolveParams struct {
	AttemptID         *uuid.UUID
	ObservationID     *uuid.UUID
	ResolutionSummary string
}
