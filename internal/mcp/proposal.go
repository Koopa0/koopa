// Copyright 2026 Koopa. All rights reserved.

// proposal.go holds the agent proposal tools: propose_area and propose_goal.
// Both mirror draft_hypothesis (hypothesis.go) — an agent writes an INERT
// draft (status=proposed) that the owner reviews and activates or rejects in
// the admin UI. The tools exist to remove Koopa's authoring-from-blank
// paralysis: an agent that has surfaced a theme or objective in conversation
// can propose it, and Koopa decides in triage.
//
// # Inertness contract
//
// A proposed goal feeds no list (GoalsByOptionalStatus with no filter excludes
// it), no alignment, and no brief (ActiveGoals filters in_progress). A proposed
// area is excluded from every active-only area selector and resolver. The only
// surfaces that show proposals are the admin triage list and the
// proposals-pending count. Activation (proposed → not_started / active) and
// rejection (hard DELETE) are owner actions in admin, off the MCP surface.
//
// # When to propose
//
// Only materialize a theme or objective that surfaced in a conversation the
// owner was part of — NEVER from a scheduled or autonomous run. This mirrors
// draft_hypothesis's pull-only clause: a proposal is a notification-worthy
// suggestion, not an autonomous write.

package mcp

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/goal"
)

// slugSep collapses every run of non-alphanumeric characters into a single
// hyphen so deriveSlug can satisfy chk_area_slug_format.
var slugSep = regexp.MustCompile(`[^a-z0-9]+`)

// deriveSlug turns a display name into a URL-safe slug matching
// chk_area_slug_format (`^[a-z0-9]+(-[a-z0-9]+)*$`): lowercase, runs of
// non-alphanumerics collapsed to single hyphens, leading/trailing hyphens
// trimmed. Returns "" when the name has no alphanumeric content — the caller
// rejects that as invalid input rather than inserting a malformed slug.
func deriveSlug(name string) string {
	return strings.Trim(slugSep.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

// --- propose_area ---

// ProposeAreaInput is the input for the propose_area tool. The created row
// always lands in status=proposed — an inert draft: the agent suggests a PARA
// theme, only the owner makes it real (activation or rejection live in the
// admin UI, off the MCP surface).
type ProposeAreaInput struct {
	As          string `json:"as,omitempty" jsonschema_description:"Self-identification — the agent making this call. Stamped on areas.created_by."`
	Name        string `json:"name" jsonschema:"required" jsonschema_description:"Display name of the proposed area (e.g. 'Backend Studio'). Required and non-blank. The slug is derived from it."`
	Description string `json:"description,omitempty" jsonschema_description:"What this area of responsibility covers and what maintaining its standard means."`
	Rationale   string `json:"rationale,omitempty" jsonschema_description:"Why this area is worth proposing now — shown to the owner in triage to support the activate/reject decision."`
}

// ProposeAreaOutput is the output of the propose_area tool.
type ProposeAreaOutput struct {
	Area *goal.ProposedArea `json:"area"`
}

func (s *Server) proposeArea(ctx context.Context, _ *mcp.CallToolRequest, input ProposeAreaInput) (*mcp.CallToolResult, ProposeAreaOutput, error) {
	if err := s.requireRegisteredCaller(ctx, "propose_area"); err != nil {
		return nil, ProposeAreaOutput{}, err
	}
	if strings.TrimSpace(input.Name) == "" {
		return nil, ProposeAreaOutput{}, fmt.Errorf("name is required")
	}
	slug := deriveSlug(input.Name)
	if slug == "" {
		return nil, ProposeAreaOutput{}, fmt.Errorf("name %q has no slug-able characters; provide a name with letters or digits", input.Name)
	}

	var created *goal.ProposedArea
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		var createErr error
		created, createErr = s.goals.WithTx(tx).ProposeArea(ctx, &goal.ProposeAreaParams{
			Slug:        slug,
			Name:        strings.TrimSpace(input.Name),
			Description: input.Description,
			CreatedBy:   s.callerIdentity(ctx),
		})
		return createErr
	})
	if err != nil {
		if errors.Is(err, goal.ErrConflict) {
			return nil, ProposeAreaOutput{}, fmt.Errorf("an area with slug %q already exists", slug)
		}
		if errors.Is(err, goal.ErrInvalidInput) {
			return nil, ProposeAreaOutput{}, fmt.Errorf("invalid area input: name must be non-blank and slug url-safe")
		}
		return nil, ProposeAreaOutput{}, fmt.Errorf("proposing area: %w", err)
	}

	s.logger.Info("propose_area", "area_id", created.ID, "slug", created.Slug, "created_by", deref(created.CreatedBy))
	return nil, ProposeAreaOutput{Area: created}, nil
}

// --- propose_goal ---

// ProposeGoalInput is the input for the propose_goal tool. The created goal
// (plus its milestones) always lands in status=proposed — an inert draft for
// the owner to activate or reject in admin triage.
type ProposeGoalInput struct {
	As          string   `json:"as,omitempty" jsonschema_description:"Self-identification — the agent making this call. Stamped on goals.created_by."`
	Area        string   `json:"area,omitempty" jsonschema_description:"Area to file the goal under: an existing ACTIVE area's slug/name, OR a just-proposed area's slug/name from the same conversation. Omit to leave the goal unclassified."`
	Title       string   `json:"title" jsonschema:"required" jsonschema_description:"One-line goal title. Required and non-blank."`
	Description string   `json:"description,omitempty" jsonschema_description:"Fuller statement of the objective and what achieving it looks like."`
	Rationale   string   `json:"rationale,omitempty" jsonschema_description:"Why this goal is worth proposing now — shown to the owner in triage."`
	Milestones  []string `json:"milestones,omitempty" jsonschema_description:"Optional ordered milestone titles created under the goal, in list order."`
}

// ProposeGoalOutput is the output of the propose_goal tool.
type ProposeGoalOutput struct {
	Goal *goal.Goal `json:"goal"`
}

//nolint:gocritic // hugeParam: input passed by value per addTool[I,O] generic contract
func (s *Server) proposeGoal(ctx context.Context, _ *mcp.CallToolRequest, input ProposeGoalInput) (*mcp.CallToolResult, ProposeGoalOutput, error) {
	if err := s.requireRegisteredCaller(ctx, "propose_goal"); err != nil {
		return nil, ProposeGoalOutput{}, err
	}
	if strings.TrimSpace(input.Title) == "" {
		return nil, ProposeGoalOutput{}, fmt.Errorf("title is required")
	}
	for i, m := range input.Milestones {
		if strings.TrimSpace(m) == "" {
			return nil, ProposeGoalOutput{}, fmt.Errorf("milestone %d is blank; every milestone needs a title", i+1)
		}
	}

	var created *goal.Goal
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		store := s.goals.WithTx(tx)

		// Resolve the area within the tx, matching proposed areas too so a
		// goal can be filed under an area proposed earlier in the same
		// conversation (the bundle case). nil area = unclassified.
		var areaID *uuid.UUID
		if id, err := resolveProposalArea(ctx, store, input.Area); err != nil {
			return err
		} else if id != nil {
			areaID = id
		}

		var createErr error
		created, createErr = store.ProposeGoal(ctx, &goal.ProposeGoalParams{
			Title:       strings.TrimSpace(input.Title),
			Description: input.Description,
			AreaID:      areaID,
			CreatedBy:   s.callerIdentity(ctx),
			Milestones:  input.Milestones,
		})
		return createErr
	})
	if err != nil {
		if errors.Is(err, goal.ErrInvalidInput) {
			return nil, ProposeGoalOutput{}, fmt.Errorf("invalid goal input: title must be non-blank")
		}
		return nil, ProposeGoalOutput{}, err
	}

	s.logger.Info("propose_goal", "goal_id", created.ID, "milestones", len(input.Milestones), "created_by", deref(created.CreatedBy))
	return nil, ProposeGoalOutput{Goal: created}, nil
}

// resolveProposalArea resolves the optional area identifier to an area_id,
// matching proposed as well as active areas. An empty identifier resolves to
// nil (unclassified). A non-empty identifier that matches no area is a clean
// caller error, not an ErrInvalidInput.
func resolveProposalArea(ctx context.Context, store *goal.Store, identifier string) (*uuid.UUID, error) {
	if strings.TrimSpace(identifier) == "" {
		return nil, nil
	}
	id, err := store.AreaIDBySlugOrNameIncludingProposed(ctx, identifier)
	if err != nil {
		if errors.Is(err, goal.ErrNotFound) {
			return nil, fmt.Errorf("no area matches %q (use an active area or one proposed earlier in this conversation)", identifier)
		}
		return nil, fmt.Errorf("resolving area %q: %w", identifier, err)
	}
	return &id, nil
}

// deref returns the pointed-to string or "" for a nil pointer — used for log
// fields where the value is provenance (created_by may be nil for seed rows,
// though a proposed row always carries the proposing agent).
func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
