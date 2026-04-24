// propose_flat.go is the MCP surface for the commitment-proposal workflow —
// seven flat tool handlers, one per entity type:
//
//   - propose_goal
//   - propose_project
//   - propose_milestone
//   - propose_directive
//   - propose_hypothesis
//   - propose_learning_plan
//   - propose_learning_domain
//
// Why flat instead of the original propose_commitment(type, fields) multiplexer:
// the seven entity types have fundamentally different required-field sets
// (goal needs area, directive needs target + priority + request_parts,
// hypothesis needs claim + invalidation_condition + content, …). The SDK's
// jsonschema:"required" tag on a typed struct generates required:[...] in
// tools/list natively, so each flat tool advertises its own contract
// without hand-written oneOf. This is the "discriminator-by-entity"
// case per .claude/rules/mcp-decision-policy.md §10. commit_proposal
// stays a single tool — the signed token carries Type and routes on
// commit side; only propose is split.
//
// Implementation split mirrors content_tools.go:
//   - propose_flat.go (this file) — MCP boundary: one typed input struct
//     + one thin handler per entity. Handlers pack typed input into the
//     map form proposeEntity consumes.
//   - commitment.go                — internal workhorse (proposeEntity
//     + resolve*Fields + signProposal). Also hosts the deprecated
//     propose_commitment shim that forwards to proposeEntity.
//
// propose_directive has a capability pre-check (SubmitTasks) at the
// handler boundary — it was commit-time in the multiplexer era, which
// wasted proposal signing round-trips for unauthorized callers.

package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/agent"
)

// ---------------------------------------------------------------
// propose_goal
// ---------------------------------------------------------------

type ProposeGoalInput struct {
	As          string  `json:"as,omitempty" jsonschema_description:"Self-identification — the agent proposing this goal."`
	Title       string  `json:"title" jsonschema:"required" jsonschema_description:"Goal title."`
	Area        *string `json:"area,omitempty" jsonschema_description:"Area slug or name. Optional; unscoped if absent."`
	AreaID      *string `json:"area_id,omitempty" jsonschema_description:"Resolved area UUID (alternative to area)."`
	Quarter     *string `json:"quarter,omitempty" jsonschema_description:"Target quarter like '2026-Q1'."`
	Deadline    *string `json:"deadline,omitempty" jsonschema_description:"ISO date YYYY-MM-DD."`
	Description *string `json:"description,omitempty" jsonschema_description:"Optional description."`
}

func (s *Server) proposeGoal(ctx context.Context, _ *mcp.CallToolRequest, input ProposeGoalInput) (*mcp.CallToolResult, ProposeCommitmentOutput, error) {
	fields := map[string]any{"title": input.Title}
	if input.Area != nil {
		fields["area"] = *input.Area
	}
	if input.AreaID != nil {
		fields["area_id"] = *input.AreaID
	}
	if input.Quarter != nil {
		fields["quarter"] = *input.Quarter
	}
	if input.Deadline != nil {
		fields["deadline"] = *input.Deadline
	}
	if input.Description != nil {
		fields["description"] = *input.Description
	}
	out, err := s.proposeEntity(ctx, "goal", fields)
	if err != nil {
		return nil, ProposeCommitmentOutput{}, err
	}
	return nil, out, nil
}

// ---------------------------------------------------------------
// propose_project
// ---------------------------------------------------------------

type ProposeProjectInput struct {
	As          string  `json:"as,omitempty" jsonschema_description:"Self-identification."`
	Title       string  `json:"title" jsonschema:"required" jsonschema_description:"Project title."`
	Slug        string  `json:"slug" jsonschema:"required" jsonschema_description:"URL-safe project slug (lowercase, kebab-case)."`
	Description *string `json:"description,omitempty" jsonschema_description:"Optional description."`
	GoalTitle   *string `json:"goal_title,omitempty" jsonschema_description:"Parent goal title (resolved to goal_id)."`
	GoalID      *string `json:"goal_id,omitempty" jsonschema_description:"Resolved goal UUID (alternative to goal_title)."`
	Area        *string `json:"area,omitempty" jsonschema_description:"Area slug or name (inherited from goal if absent)."`
	AreaID      *string `json:"area_id,omitempty" jsonschema_description:"Resolved area UUID."`
}

func (s *Server) proposeProject(ctx context.Context, _ *mcp.CallToolRequest, input ProposeProjectInput) (*mcp.CallToolResult, ProposeCommitmentOutput, error) {
	fields := map[string]any{"title": input.Title, "slug": input.Slug}
	if input.Description != nil {
		fields["description"] = *input.Description
	}
	if input.GoalTitle != nil {
		fields["goal_title"] = *input.GoalTitle
	}
	if input.GoalID != nil {
		fields["goal_id"] = *input.GoalID
	}
	if input.Area != nil {
		fields["area"] = *input.Area
	}
	if input.AreaID != nil {
		fields["area_id"] = *input.AreaID
	}
	out, err := s.proposeEntity(ctx, "project", fields)
	if err != nil {
		return nil, ProposeCommitmentOutput{}, err
	}
	return nil, out, nil
}

// ---------------------------------------------------------------
// propose_milestone
// ---------------------------------------------------------------

type ProposeMilestoneInput struct {
	As          string  `json:"as,omitempty" jsonschema_description:"Self-identification."`
	Title       string  `json:"title" jsonschema:"required" jsonschema_description:"Milestone title."`
	GoalTitle   *string `json:"goal_title,omitempty" jsonschema_description:"Parent goal title (resolved to goal_id). At least one of goal_title / goal_id is required."`
	GoalID      *string `json:"goal_id,omitempty" jsonschema_description:"Resolved goal UUID (alternative to goal_title)."`
	Description *string `json:"description,omitempty" jsonschema_description:"Optional description."`
	Deadline    *string `json:"deadline,omitempty" jsonschema_description:"Target deadline as ISO date YYYY-MM-DD."`
}

func (s *Server) proposeMilestone(ctx context.Context, _ *mcp.CallToolRequest, input ProposeMilestoneInput) (*mcp.CallToolResult, ProposeCommitmentOutput, error) {
	fields := map[string]any{"title": input.Title}
	if input.GoalTitle != nil {
		fields["goal_title"] = *input.GoalTitle
	}
	if input.GoalID != nil {
		fields["goal_id"] = *input.GoalID
	}
	if input.Description != nil {
		fields["description"] = *input.Description
	}
	if input.Deadline != nil {
		fields["deadline"] = *input.Deadline
	}
	out, err := s.proposeEntity(ctx, "milestone", fields)
	if err != nil {
		return nil, ProposeCommitmentOutput{}, err
	}
	return nil, out, nil
}

// ---------------------------------------------------------------
// propose_directive
// ---------------------------------------------------------------

type ProposeDirectiveInput struct {
	As           string            `json:"as,omitempty" jsonschema_description:"Self-identification (source agent). Inferred from the caller identity when absent."`
	Title        *string           `json:"title,omitempty" jsonschema_description:"Short human-readable title. Defaults to 'Directive' if absent."`
	Source       *string           `json:"source,omitempty" jsonschema_description:"Source agent name. Inferred from the caller identity when absent."`
	Target       string            `json:"target" jsonschema:"required" jsonschema_description:"Target agent name (must exist in the registry)."`
	Priority     string            `json:"priority" jsonschema:"required" jsonschema_description:"One of: high, medium, low."`
	RequestParts []json.RawMessage `json:"request_parts" jsonschema:"required" jsonschema_description:"Directive payload as a2a.Part array: [{\"text\":\"...\"}] or [{\"data\":{...}}]."`
	Metadata     json.RawMessage   `json:"metadata,omitempty" jsonschema_description:"Optional directive metadata (any JSON object)."`
}

// proposeDirective performs the capability pre-check (ActionSubmitTask)
// at propose time rather than at commit time. The original multiplexer
// let a caller without SubmitTasks sign a proposal token and only
// rejected them at commit_proposal — four round-trips wasted. This
// fast-fails the unauthorized caller before we allocate a signed token.
//
//nolint:gocritic // hugeParam: input passed by value per addTool[I,O] generic contract
func (s *Server) proposeDirective(ctx context.Context, _ *mcp.CallToolRequest, input ProposeDirectiveInput) (*mcp.CallToolResult, ProposeCommitmentOutput, error) {
	caller := agent.Name(s.callerIdentity(ctx))
	if _, err := agent.Authorize(ctx, s.registry, caller, agent.ActionSubmitTask); err != nil {
		return nil, ProposeCommitmentOutput{}, fmt.Errorf("propose_directive: %w", err)
	}

	fields := map[string]any{
		"target":        input.Target,
		"priority":      input.Priority,
		"request_parts": input.RequestParts,
	}
	if input.Title != nil {
		fields["title"] = *input.Title
	}
	if input.Source != nil {
		fields["source"] = *input.Source
	}
	if len(input.Metadata) > 0 {
		// resolveDirectiveFields + commitDirective handle metadata as any,
		// then json.Marshal it into the task.metadata column. Pass the
		// raw message through unchanged.
		var m any
		if err := json.Unmarshal(input.Metadata, &m); err != nil {
			return nil, ProposeCommitmentOutput{}, fmt.Errorf("propose_directive: metadata is not valid JSON: %w", err)
		}
		fields["metadata"] = m
	}

	out, err := s.proposeEntity(ctx, "directive", fields)
	if err != nil {
		return nil, ProposeCommitmentOutput{}, err
	}
	return nil, out, nil
}

// ---------------------------------------------------------------
// propose_hypothesis
// ---------------------------------------------------------------

type ProposeHypothesisInput struct {
	As                    string `json:"as,omitempty" jsonschema_description:"Self-identification."`
	Claim                 string `json:"claim" jsonschema:"required" jsonschema_description:"The falsifiable claim being proposed."`
	InvalidationCondition string `json:"invalidation_condition" jsonschema:"required" jsonschema_description:"What outcome would invalidate the claim — required to keep hypotheses testable."`
	Content               string `json:"content" jsonschema:"required" jsonschema_description:"Full hypothesis narrative (context, reasoning)."`
}

func (s *Server) proposeHypothesis(ctx context.Context, _ *mcp.CallToolRequest, input ProposeHypothesisInput) (*mcp.CallToolResult, ProposeCommitmentOutput, error) {
	fields := map[string]any{
		"claim":                  input.Claim,
		"invalidation_condition": input.InvalidationCondition,
		"content":                input.Content,
	}
	out, err := s.proposeEntity(ctx, "hypothesis", fields)
	if err != nil {
		return nil, ProposeCommitmentOutput{}, err
	}
	return nil, out, nil
}

// ---------------------------------------------------------------
// propose_learning_plan
// ---------------------------------------------------------------

type ProposeLearningPlanInput struct {
	As          string  `json:"as,omitempty" jsonschema_description:"Self-identification."`
	Title       string  `json:"title" jsonschema:"required" jsonschema_description:"Learning plan title."`
	Domain      string  `json:"domain" jsonschema:"required" jsonschema_description:"Learning domain slug (must exist in learning_domains)."`
	Description *string `json:"description,omitempty" jsonschema_description:"Optional description."`
	GoalID      *string `json:"goal_id,omitempty" jsonschema_description:"Optional parent goal UUID."`
}

func (s *Server) proposeLearningPlan(ctx context.Context, _ *mcp.CallToolRequest, input ProposeLearningPlanInput) (*mcp.CallToolResult, ProposeCommitmentOutput, error) {
	fields := map[string]any{"title": input.Title, "domain": input.Domain}
	if input.Description != nil {
		fields["description"] = *input.Description
	}
	if input.GoalID != nil {
		fields["goal_id"] = *input.GoalID
	}
	out, err := s.proposeEntity(ctx, "learning_plan", fields)
	if err != nil {
		return nil, ProposeCommitmentOutput{}, err
	}
	return nil, out, nil
}

// ---------------------------------------------------------------
// propose_learning_domain
// ---------------------------------------------------------------

type ProposeLearningDomainInput struct {
	As          string  `json:"as,omitempty" jsonschema_description:"Self-identification."`
	Slug        string  `json:"slug" jsonschema:"required" jsonschema_description:"Domain slug — lowercase, kebab-case, matches pattern ^[a-z][a-z0-9-]*$."`
	Name        string  `json:"name" jsonschema:"required" jsonschema_description:"Display name."`
	Description *string `json:"description,omitempty" jsonschema_description:"Optional description (metadata only; not stored on learning_domains today — surfaces as a warning)."`
}

func (s *Server) proposeLearningDomain(ctx context.Context, _ *mcp.CallToolRequest, input ProposeLearningDomainInput) (*mcp.CallToolResult, ProposeCommitmentOutput, error) {
	fields := map[string]any{"slug": input.Slug, "name": input.Name}
	if input.Description != nil {
		fields["description"] = *input.Description
	}
	out, err := s.proposeEntity(ctx, "learning_domain", fields)
	if err != nil {
		return nil, ProposeCommitmentOutput{}, err
	}
	return nil, out, nil
}
