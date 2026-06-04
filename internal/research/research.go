// Copyright 2026 Koopa. All rights reserved.

// Package research provides storage for fan-out research: dispatched
// assignments and the agent-produced report corpus.
//
// A report is a first-class knowledge-corpus member, low_trust by default, and
// is intentionally distinct from both notes and contents:
//
//   - note    — Koopa/human-digested private knowledge, maturity axis
//     (seed → evergreen). Lives in internal/note.
//   - content — editorial / publication material, status axis
//     (draft → published). Lives in internal/content.
//   - report  — agent-produced research/source artifact, TRUST axis
//     (low_trust → trusted). Lives here.
//
// The trust axis is NOT note maturity: a trusted report is still a SOURCE, never
// "evergreen digested knowledge". Trust promotion is a human/admin verdict
// (SetTrust is schema/store-ready; no production human UI consumes it yet —
// deferred), never an agent-facing MCP action. Reports are searchable from
// creation and downranked by trust — visibility is not gated.
//
// A research assignment is fan-out only: HQ/human dispatches a topic to an
// agent; the agent fulfills it by creating a report referencing the assignment,
// which flips the assignment open → fulfilled. There is no chaining, no task
// tree, and no acceptance ceremony — that is the A2A tasks entity, not this one.
package research

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// TrustStatus is the trust axis of a report. Mirrors the reports.trust_status
// TEXT + CHECK column (not a PG enum).
type TrustStatus string

const (
	// TrustLow is the birth state of every agent report: unverified.
	TrustLow TrustStatus = "low_trust"
	// TrustTrusted is set by a human/admin verdict that the report is a
	// credible source. It remains a source, not digested knowledge.
	TrustTrusted TrustStatus = "trusted"
)

// Valid reports whether t is a recognized trust status.
func (t TrustStatus) Valid() bool {
	switch t {
	case TrustLow, TrustTrusted:
		return true
	default:
		return false
	}
}

// Status is the lifecycle of a research assignment. Mirrors the
// research_assignments.status TEXT + CHECK column.
type Status string

const (
	// StatusOpen is a dispatched assignment with no report yet. It is persisted
	// and store-queryable (OpenAssignments), but no agent-facing read tool
	// surfaces open assignments yet — that is a reserved future read surface.
	StatusOpen Status = "open"
	// StatusFulfilled means a report referencing this assignment exists.
	StatusFulfilled Status = "fulfilled"
)

// Valid reports whether s is a recognized assignment status.
func (s Status) Valid() bool {
	switch s {
	case StatusOpen, StatusFulfilled:
		return true
	default:
		return false
	}
}

// Report is an agent-produced research/source artifact as stored.
type Report struct {
	ID                 uuid.UUID   `json:"id"`
	Title              string      `json:"title"`
	Body               string      `json:"body"`
	ProducedBy         string      `json:"produced_by"`
	OriginAssignmentID *uuid.UUID  `json:"origin_assignment_id,omitempty"`
	TrustStatus        TrustStatus `json:"trust_status"`
	CreatedAt          time.Time   `json:"created_at"`
	UpdatedAt          time.Time   `json:"updated_at"`
}

// Assignment is a dispatched fan-out research task as stored.
type Assignment struct {
	ID          uuid.UUID  `json:"id"`
	Topic       string     `json:"topic"`
	AssignedTo  string     `json:"assigned_to"`
	AssignedBy  string     `json:"assigned_by"`
	Status      Status     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	FulfilledAt *time.Time `json:"fulfilled_at,omitempty"`
}

// CreateReportParams are the required fields for Store.CreateReport. TrustStatus
// is intentionally absent — every report is born low_trust; promotion is a
// separate human action.
type CreateReportParams struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	// ProducedBy is required provenance — the agent that produced the report.
	ProducedBy string `json:"produced_by"`
	// OriginAssignmentID links the report to the fan-out assignment it fulfills.
	// Nil for a standalone report (no dispatched assignment).
	OriginAssignmentID *uuid.UUID `json:"origin_assignment_id,omitempty"`
}

// CreateAssignmentParams are the required fields for Store.CreateAssignment.
type CreateAssignmentParams struct {
	Topic      string `json:"topic"`
	AssignedTo string `json:"assigned_to"`
	AssignedBy string `json:"assigned_by"`
}

var (
	// ErrNotFound indicates the report or assignment does not exist.
	ErrNotFound = errors.New("research: not found")

	// ErrUnknownAgent indicates a referenced agent name (produced_by /
	// assigned_to / assigned_by) is not in the agents registry — surfaced from
	// a foreign-key violation.
	ErrUnknownAgent = errors.New("research: unknown agent")

	// ErrNotAssignee indicates a caller tried to fulfill an assignment that is
	// dispatched to a different agent. Fan-out research is targeted work, not an
	// open bounty — only the assignee may fulfill it.
	ErrNotAssignee = errors.New("research: caller is not the assignment's assignee")

	// ErrInvalidTrust signals an unrecognized trust status on input.
	ErrInvalidTrust = errors.New("research: invalid trust status")
)
