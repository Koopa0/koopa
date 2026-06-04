// Copyright 2026 Koopa. All rights reserved.

// report.go holds the fan-out research MCP tools: assign_research and
// create_report.
//
//	assign_research — HQ/human dispatches a research topic to an agent.
//	create_report   — the agent files a low-trust, searchable report; passing
//	                  origin_assignment_id fulfills the dispatching assignment.
//
// An assignment is fulfilled by the report's existence — there is no acceptance
// handshake and no task-completion artifact. Fan-out research is neither the
// A2A coordination path (tasks / file_report) nor chained delegation. Trust
// promotion (low_trust → trusted), formal revision, and final acceptance are
// human/admin actions and are not exposed here; report trust lives only behind
// research.Store.SetTrust.
//
// Authorization:
//   - assign_research is author-gated to hq (+ human implicit): dispatch is a
//     coordinator act, mirroring plan_day. Studios do not dispatch.
//   - create_report accepts any registered caller for a STANDALONE report
//     (mirrors create_note: born low_trust + badged, so trust — not the write
//     gate — is the safety; produced_by is stamped from the caller). Fulfilling
//     an assignment (origin_assignment_id) additionally requires the caller to
//     BE that assignment's assigned_to, so targeted fan-out work cannot be
//     closed by the wrong agent.

package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/research"
)

// ReportDetail is the wire shape for a single report in tool replies.
type ReportDetail struct {
	ID                 string `json:"id"`
	Title              string `json:"title"`
	Body               string `json:"body"`
	ProducedBy         string `json:"produced_by"`
	OriginAssignmentID string `json:"origin_assignment_id,omitempty"`
	TrustStatus        string `json:"trust_status"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
}

// ReportReply is the reply envelope for create_report.
type ReportReply struct {
	Report *ReportDetail `json:"report"`
}

// AssignmentDetail is the wire shape for a single research assignment.
type AssignmentDetail struct {
	ID          string `json:"id"`
	Topic       string `json:"topic"`
	AssignedTo  string `json:"assigned_to"`
	AssignedBy  string `json:"assigned_by"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	FulfilledAt string `json:"fulfilled_at,omitempty"`
}

// AssignmentReply is the reply envelope for assign_research.
type AssignmentReply struct {
	Assignment *AssignmentDetail `json:"assignment"`
}

// ---------------------------------------------------------------
// assign_research
// ---------------------------------------------------------------

// AssignResearchInput is the tight input for assign_research.
type AssignResearchInput struct {
	As         string `json:"as,omitempty" jsonschema_description:"Self-identification — the dispatching agent. Stamped on research_assignments.assigned_by."`
	Topic      string `json:"topic" jsonschema:"required" jsonschema_description:"What to research. Non-blank."`
	AssignedTo string `json:"assigned_to" jsonschema:"required" jsonschema_description:"The agent (registry name) expected to produce the report, e.g. research-lab."`
}

func (s *Server) assignResearch(ctx context.Context, _ *mcp.CallToolRequest, input AssignResearchInput) (*mcp.CallToolResult, AssignmentReply, error) {
	// Dispatch is a coordinator act: hq (+ human implicit). Studios do not
	// dispatch fan-out research, so they are excluded here.
	if err := s.requireAuthor(ctx, "assign_research", "hq"); err != nil {
		return nil, AssignmentReply{}, err
	}
	if input.Topic == "" {
		return nil, AssignmentReply{}, fmt.Errorf("topic is required")
	}
	if input.AssignedTo == "" {
		return nil, AssignmentReply{}, fmt.Errorf("assigned_to is required")
	}

	// Single INSERT, no transaction. The report lane is deliberately
	// un-audited — migrations/004_report_lane.up.sql adds no activity_events
	// trigger on research_assignments — so there is no koopa.actor for a
	// trigger to consume and withActorTx would buy nothing here. Provenance
	// (assigned_by) lives on the row itself.
	a, err := s.research.CreateAssignment(ctx, research.CreateAssignmentParams{
		Topic:      input.Topic,
		AssignedTo: input.AssignedTo,
		AssignedBy: s.callerIdentity(ctx),
	})
	if err != nil {
		if errors.Is(err, research.ErrUnknownAgent) {
			return nil, AssignmentReply{}, fmt.Errorf("unknown agent %q (assigned_to must be a registered agent name)", input.AssignedTo)
		}
		return nil, AssignmentReply{}, fmt.Errorf("assigning research: %w", err)
	}

	s.logger.Info("assign_research", "id", a.ID, "assigned_to", a.AssignedTo)
	return nil, AssignmentReply{Assignment: toAssignmentDetail(a)}, nil
}

// ---------------------------------------------------------------
// create_report
// ---------------------------------------------------------------

// CreateReportInput is the tight input for create_report. trust_status is
// intentionally NOT accepted — every report is born low_trust; promotion is a
// human/admin verdict.
type CreateReportInput struct {
	As                 string `json:"as,omitempty" jsonschema_description:"Self-identification — the producing agent. Stamped on reports.produced_by."`
	Title              string `json:"title" jsonschema:"required" jsonschema_description:"Short title/summary of the report. Non-blank."`
	Body               string `json:"body,omitempty" jsonschema_description:"Report body in markdown (the research/source content). Defaults to empty."`
	OriginAssignmentID string `json:"origin_assignment_id,omitempty" jsonschema_description:"UUID of the research assignment this report fulfills. Omit for a standalone report. When set, the assignment is marked fulfilled."`
}

func (s *Server) createReport(ctx context.Context, _ *mcp.CallToolRequest, input CreateReportInput) (*mcp.CallToolResult, ReportReply, error) {
	if err := s.requireRegisteredCaller(ctx, "create_report"); err != nil {
		return nil, ReportReply{}, err
	}
	// Filing into the searchable report corpus requires the PublishArtifacts
	// capability — the same bar file_report(standalone) sets for publishing an
	// agent deliverable. This excludes the capability-less agents (claude web,
	// koopa0-dev, go-spec) and the human, whose own writing is notes/content
	// rather than low-trust agent sources. Checked before assignee resolution
	// so a capability-less caller is refused regardless of origin_assignment_id.
	caller := agent.Name(s.callerIdentity(ctx))
	if _, err := agent.Authorize(ctx, s.registry, caller, agent.ActionPublishArtifact); err != nil {
		return nil, ReportReply{}, fmt.Errorf("create_report: %w", err)
	}
	if input.Title == "" {
		return nil, ReportReply{}, fmt.Errorf("title is required")
	}

	originID, err := s.resolveAssignmentForFulfillment(ctx, input.OriginAssignmentID)
	if err != nil {
		return nil, ReportReply{}, err
	}

	// withActorTx is load-bearing here: the report INSERT and the assignment
	// open→fulfilled flip must commit atomically. The koopa.actor it binds is
	// currently inert (the report lane has no audit trigger — see
	// migrations/004_report_lane.up.sql), but the transaction is the real need
	// and stays forward-compatible if audit is added later.
	var r *research.Report
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		var createErr error
		r, createErr = s.research.WithTx(tx).CreateReport(ctx, research.CreateReportParams{
			Title:              input.Title,
			Body:               input.Body,
			ProducedBy:         s.callerIdentity(ctx),
			OriginAssignmentID: originID,
		})
		return createErr
	})
	if err != nil {
		if errors.Is(err, research.ErrNotFound) {
			return nil, ReportReply{}, fmt.Errorf("origin assignment %s not found", input.OriginAssignmentID)
		}
		if errors.Is(err, research.ErrUnknownAgent) {
			return nil, ReportReply{}, fmt.Errorf("producing agent is not registered")
		}
		return nil, ReportReply{}, fmt.Errorf("creating report: %w", err)
	}

	s.logger.Info("create_report", "id", r.ID, "trust", r.TrustStatus, "origin", r.OriginAssignmentID)
	return nil, ReportReply{Report: toReportDetail(r)}, nil
}

// ---------------------------------------------------------------
// helpers
// ---------------------------------------------------------------

// resolveAssignmentForFulfillment parses an optional origin_assignment_id and,
// when present, enforces the self-bound rule (authorization-matrix §1 Axis 4):
// only the agent the assignment is dispatched to may fulfill it — targeted
// fan-out work is not an open bounty. assigned_to is immutable, so this
// pre-write check is race-free; an assignment deleted before the insert
// surfaces later as a foreign-key ErrNotFound. Returns nil for a standalone
// report (no origin), which any registered caller may file.
func (s *Server) resolveAssignmentForFulfillment(ctx context.Context, raw string) (*uuid.UUID, error) {
	if raw == "" {
		return nil, nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid origin_assignment_id: %w", err)
	}
	a, err := s.research.Assignment(ctx, id)
	if err != nil {
		if errors.Is(err, research.ErrNotFound) {
			return nil, fmt.Errorf("origin assignment %s not found", raw)
		}
		return nil, fmt.Errorf("loading origin assignment: %w", err)
	}
	if a.AssignedTo != s.callerIdentity(ctx) {
		return nil, fmt.Errorf("%w: assignment %s is assigned to %q", research.ErrNotAssignee, raw, a.AssignedTo)
	}
	return &id, nil
}

func toReportDetail(r *research.Report) *ReportDetail {
	if r == nil {
		return nil
	}
	d := &ReportDetail{
		ID:          r.ID.String(),
		Title:       r.Title,
		Body:        r.Body,
		ProducedBy:  r.ProducedBy,
		TrustStatus: string(r.TrustStatus),
		CreatedAt:   r.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   r.UpdatedAt.Format(time.RFC3339),
	}
	if r.OriginAssignmentID != nil {
		d.OriginAssignmentID = r.OriginAssignmentID.String()
	}
	return d
}

func toAssignmentDetail(a *research.Assignment) *AssignmentDetail {
	if a == nil {
		return nil
	}
	d := &AssignmentDetail{
		ID:         a.ID.String(),
		Topic:      a.Topic,
		AssignedTo: a.AssignedTo,
		AssignedBy: a.AssignedBy,
		Status:     string(a.Status),
		CreatedAt:  a.CreatedAt.Format(time.RFC3339),
	}
	if a.FulfilledAt != nil {
		d.FulfilledAt = a.FulfilledAt.Format(time.RFC3339)
	}
	return d
}
