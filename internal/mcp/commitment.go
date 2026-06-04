// Copyright 2026 Koopa. All rights reserved.

// commitment.go holds the two-phase commitment MCP tools: the seven
// typed propose_<type> tools (in propose_flat.go) and commit_proposal
// (here). This is the approved pattern for any entity that requires
// explicit human endorsement — goal, project, milestone, hypothesis,
// learning_plan, learning_domain, directive. See
// .claude/rules/mcp-decision-policy.md §8 for the proposal-first matrix.
//
// The HMAC signing/verification lives in proposal.go. This file owns
// per-type field validation (resolveProposalFields and its siblings)
// and the commit branch that turns a verified token into a domain
// entity insert.

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/learning/hypothesis"
	"github.com/Koopa0/koopa/internal/learning/plan"
	"github.com/Koopa0/koopa/internal/project"
)

// slugPattern mirrors every chk_*_slug_format CHECK constraint in
// migrations/001 (learning_domains, concepts, contents, tags, topics,
// observation_categories, ...). Validating client-side lets handlers
// return a specific error instead of a generic CheckViolation from PG.
//
// Replaced an earlier learningDomainSlugPattern (^[a-z][a-z0-9-]*$) which
// drifted from the schema in two directions: it required a letter as the
// first character (the schema allows leading digits — e.g. "n2-grammar"
// is a legal slug) and it allowed trailing/consecutive hyphens (the
// schema rejects both). The canonical form below is strictly aligned
// with the DB so a slug accepted here is always accepted by INSERT.
//
// If a future migration changes the schema rule, update this regex in
// the same commit so client-side and server-side stay aligned.
var slugPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// validateSlug returns an error suitable for caller-facing messages
// when s does not match slugPattern. fieldName is the human-readable
// name to show ("concept slug", "content slug", "observation category").
// Returns nil for valid slugs. The error wording is intentionally close
// to commitment.go::resolveLearningDomainFields so all slug rejections
// look the same regardless of which entity the caller was creating.
func validateSlug(fieldName, s string) error {
	if slugPattern.MatchString(s) {
		return nil
	}
	return fmt.Errorf("invalid %s %q: must be lowercase kebab-case (pattern: %s)", fieldName, s, slugPattern.String())
}

// ProposeOutput is the response shape shared by every typed
// propose_<type> tool. Preview echoes the resolved fields the caller
// will commit; ProposalToken is the HMAC-signed payload that
// commit_proposal verifies.
type ProposeOutput struct {
	Type          string         `json:"type"`
	Preview       map[string]any `json:"preview"`
	Warnings      []string       `json:"warnings"`
	ProposalToken string         `json:"proposal_token"`
}

// proposeEntity is the internal workhorse the seven flat propose_*
// tools share. Centralizes the type-validate → resolve-fields →
// sign-proposal dance so each typed handler stays small. The 'type'
// parameter comes from the tool call site (each flat tool knows its
// own type). Fields is the map form resolveProposalFields accepts —
// flat tools pack their typed input into this shape before calling
// through.
func (s *Server) proposeEntity(ctx context.Context, entityType string, fields map[string]any) (ProposeOutput, error) {
	switch entityType {
	case "goal", "project", "milestone", "hypothesis", "learning_plan", "learning_domain":
		// valid
	default:
		return ProposeOutput{}, fmt.Errorf("invalid type %q (valid: goal, project, milestone, hypothesis, learning_plan, learning_domain)", entityType)
	}

	resolved, warnings, err := s.resolveProposalFields(ctx, entityType, fields)
	if err != nil {
		return ProposeOutput{}, fmt.Errorf("proposal rejected: %w", err)
	}

	token, err := signProposal(s.proposalSecret, entityType, resolved)
	if err != nil {
		return ProposeOutput{}, fmt.Errorf("signing proposal: %w", err)
	}

	s.logger.Info("propose_entity", "type", entityType)
	return ProposeOutput{
		Type:          entityType,
		Preview:       resolved,
		Warnings:      warnings,
		ProposalToken: token,
	}, nil
}

// resolveProposalFields validates and resolves references in proposal fields.
// Returns err when a required field is missing or fails structural validation;
// proposeEntity must NOT sign a token in that case. Warnings communicate
// non-fatal drift (fuzzy lookups, optional fields absent) that the caller may
// address before commit.
func (s *Server) resolveProposalFields(ctx context.Context, entityType string, fields map[string]any) (resolved map[string]any, warnings []string, err error) {
	resolved = make(map[string]any, len(fields))
	for k, v := range fields {
		resolved[k] = v
	}

	switch entityType {
	case "goal":
		warnings, err = s.resolveGoalFields(ctx, resolved)
	case "project":
		warnings, err = s.resolveProjectFields(ctx, resolved)
	case "milestone":
		warnings, err = s.resolveMilestoneFields(ctx, resolved)
	case "hypothesis":
		warnings, err = resolveHypothesisFields(resolved)
	case "learning_plan":
		warnings, err = s.resolveLearningPlanFields(ctx, resolved)
	case "learning_domain":
		warnings, err = s.resolveLearningDomainFields(ctx, resolved)
	}
	return resolved, warnings, err
}

func (s *Server) resolveGoalFields(ctx context.Context, f map[string]any) (warnings []string, err error) {
	if title, ok := f["title"].(string); !ok || title == "" {
		return nil, fmt.Errorf("title is required for goal")
	}
	// Resolve area slug/name → area_id UUID. Area is optional — missing or
	// unresolvable area is a warning, not an error.
	if areaSlug, ok := f["area"].(string); ok && areaSlug != "" {
		areaID, aErr := s.goals.AreaIDBySlugOrName(ctx, areaSlug)
		if aErr == nil {
			f["area_id"] = areaID.String()
			delete(f, "area")
		} else {
			warnings = append(warnings, fmt.Sprintf("area %q not found — goal will be unscoped", areaSlug))
		}
	} else if _, ok := f["area_id"]; !ok {
		warnings = append(warnings, "no area specified — goal will be unscoped")
	}
	return warnings, nil
}

func (s *Server) resolveProjectFields(ctx context.Context, f map[string]any) (warnings []string, err error) {
	if title, ok := f["title"].(string); !ok || title == "" {
		return nil, fmt.Errorf("title is required for project")
	}
	if slug, ok := f["slug"].(string); !ok || slug == "" {
		return nil, fmt.Errorf("slug is required for project")
	}
	if goalTitle, ok := f["goal_title"].(string); ok && goalTitle != "" {
		if g, gErr := s.goals.GoalByTitle(ctx, goalTitle); gErr == nil {
			f["goal_id"] = g.ID.String()
		} else {
			warnings = append(warnings, fmt.Sprintf("goal %q not found", goalTitle))
		}
		delete(f, "goal_title")
	}
	return warnings, nil
}

func (s *Server) resolveMilestoneFields(ctx context.Context, f map[string]any) (warnings []string, err error) {
	if title, ok := f["title"].(string); !ok || title == "" {
		return nil, fmt.Errorf("title is required for milestone")
	}
	if goalTitle, ok := f["goal_title"].(string); ok && goalTitle != "" {
		if g, gErr := s.goals.GoalByTitle(ctx, goalTitle); gErr == nil {
			f["goal_id"] = g.ID.String()
		} else {
			warnings = append(warnings, fmt.Sprintf("goal %q not found — milestone must belong to a goal", goalTitle))
		}
		delete(f, "goal_title")
	}
	// After goal_title resolution above, either goal_id is set or the caller
	// must supply one directly. Milestone without a goal FK violates the
	// schema, so this is an error not a warning.
	if _, ok := f["goal_id"]; !ok {
		return warnings, fmt.Errorf("goal_title or goal_id is required for milestone")
	}
	return warnings, nil
}

// isValidTaskPriority reports whether p matches the tasks.priority CHECK
// constraint vocabulary. Mirrors the enum in migrations/001_initial.up.sql.
func isValidTaskPriority(p string) bool {
	switch p {
	case "high", "medium", "low":
		return true
	default:
		return false
	}
}

// isValidEnergy mirrors the todos.energy CHECK in 001_initial.up.sql.
// Used by capture_inbox and advance_work(action=clarify).
func isValidEnergy(e string) bool {
	switch e {
	case "high", "medium", "low":
		return true
	default:
		return false
	}
}

// isValidContentStatus mirrors the contents.status CHECK.
func isValidContentStatus(s string) bool {
	switch s {
	case "draft", "review", "published", "archived":
		return true
	default:
		return false
	}
}

// isValidPlanEntryStatus mirrors the values manage_plan(action=update_entry)
// is allowed to write to learning_plan_entries.status.
func isValidPlanEntryStatus(s string) bool {
	switch s {
	case "completed", "skipped", "substituted":
		return true
	default:
		return false
	}
}

// isValidPlanStatus mirrors the values manage_plan(action=update_plan) is
// allowed to write to learning_plans.status.
func isValidPlanStatus(s string) bool {
	switch s {
	case "active", "paused", "completed", "abandoned":
		return true
	default:
		return false
	}
}

// isValidGoalStatusFilter accepts the read-side filter values for goals.
// "all" is a UI sentinel meaning "every status"; the rest mirror the
// goals.status CHECK.
func isValidGoalStatusFilter(s string) bool {
	switch s {
	case "all", "not_started", "in_progress", "done", "abandoned", "on_hold":
		return true
	default:
		return false
	}
}

//nolint:unparam // uniform (warnings, err) signature with sibling resolve*Fields
func resolveHypothesisFields(f map[string]any) (warnings []string, err error) {
	if claim, ok := f["claim"].(string); !ok || claim == "" {
		return nil, fmt.Errorf("claim is required for hypothesis")
	}
	if cond, ok := f["invalidation_condition"].(string); !ok || cond == "" {
		return nil, fmt.Errorf("invalidation_condition is required for hypothesis")
	}
	if content, ok := f["content"].(string); !ok || content == "" {
		return nil, fmt.Errorf("content is required for hypothesis")
	}
	return nil, nil
}

// --- commit_proposal ---

// CommitProposalInput is the input for the commit_proposal tool.
type CommitProposalInput struct {
	ProposalToken string         `json:"proposal_token" jsonschema:"required" jsonschema_description:"Token returned by any propose_<type> tool"`
	Modifications map[string]any `json:"modifications,omitempty" jsonschema_description:"Optional field overrides before commit"`
}

// CommitProposalOutput is the output of the commit_proposal tool.
type CommitProposalOutput struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Committed bool   `json:"committed"`
}

// commitProposal turns a verified proposal token into a domain insert.
// The two-phase pattern's load-bearing semantic is "agent drafts, human
// confirms" — without enforcement here the propose+token machinery is
// theatre, since any caller carrying a valid token could finalize the
// write.
//
// The gate dispatches on payload.Type:
//
//   - directive: inter-agent coordination, NOT a commitment to Koopa.
//     HQ commits its own delegation tokens in the same session. The
//     existing SubmitTasks capability check inside commitDirective is
//     the right gate; layering a human requirement on top would force
//     Koopa to confirm every cross-agent task and turn HQ into a
//     paperwork bottleneck.
//
//   - goal / project / milestone / hypothesis / learning_plan /
//     learning_domain: each reshapes Koopa's commitment surface in some
//     way (quarterly horizon, multi-week scope, falsifiable claim
//     tracker, learning taxonomy). These commit only with explicit
//     human authority via requireExplicitHuman — see authz.go for why
//     "explicit" matters.
func (s *Server) commitProposal(ctx context.Context, _ *mcp.CallToolRequest, input CommitProposalInput) (*mcp.CallToolResult, CommitProposalOutput, error) {
	payload, err := verifyProposal(s.proposalSecret, input.ProposalToken)
	if err != nil {
		return nil, CommitProposalOutput{}, fmt.Errorf("invalid proposal: %w", err)
	}

	// All authorization MUST complete before the nonce is consumed, so an
	// unauthorized attempt can never burn a legitimate proposer's token (the
	// consume is single-use-on-claim; a burned token is dead until expiry).
	// Every commitment type requires explicit human authority.
	if err := s.requireExplicitHuman(ctx, "commit_proposal of "+payload.Type); err != nil {
		return nil, CommitProposalOutput{}, err
	}

	// Consume the token's nonce — the replay defense, and always the LAST step
	// after authorization passes. A valid token commits at most once: the claim
	// is atomic, so a replay (sequential or concurrent) is rejected here with a
	// clear error rather than silently creating a second entity.
	if !s.nonces.consume(payload.Nonce, payload.ExpiresAt+int64(proposalNonceRetention.Seconds()), time.Now().Unix()) {
		return nil, CommitProposalOutput{}, fmt.Errorf("proposal_already_committed: this proposal token has already been committed; re-propose to make another change")
	}

	// Apply modifications.
	fields := payload.Fields
	for k, v := range input.Modifications {
		fields[k] = v
	}

	id, err := s.commitEntity(ctx, payload.Type, fields)
	if err != nil {
		// The nonce is already consumed (single-use-on-claim), so this token is
		// now spent — surface that explicitly rather than returning the bare
		// downstream error as if a retry with the same token were possible.
		// %w preserves the underlying cause for errors.Is/As callers.
		return nil, CommitProposalOutput{}, fmt.Errorf("commit failed after the proposal token was consumed; the token is now spent — re-propose to retry: %w", err)
	}

	s.logger.Info("commit_proposal", "type", payload.Type, "id", id)
	return nil, CommitProposalOutput{
		Type:      payload.Type,
		ID:        id,
		Committed: true,
	}, nil
}

// commitEntity creates the entity in the database.
func (s *Server) commitEntity(ctx context.Context, entityType string, fields map[string]any) (string, error) {
	switch entityType {
	case "goal":
		return s.commitGoal(ctx, fields)
	case "project":
		return s.commitProject(ctx, fields)
	case "milestone":
		return s.commitMilestone(ctx, fields)
	case "hypothesis":
		return s.commitHypothesis(ctx, fields)
	case "learning_plan":
		return s.commitLearningPlan(ctx, fields)
	case "learning_domain":
		return s.commitLearningDomain(ctx, fields)
	default:
		return "", fmt.Errorf("unknown entity type: %s", entityType)
	}
}

// propValidatorDrift logs a warning when commit-side catches a required-field
// violation that propose-side should have rejected. If this log ever fires in
// production it is a bug in the corresponding resolve<Entity>Fields function.
func (s *Server) propValidatorDrift(entity, field string) {
	s.logger.Warn("proposal validator drift — commit caught missing required field",
		"entity", entity, "field", field)
}

func (s *Server) commitGoal(ctx context.Context, fields map[string]any) (string, error) {
	title, _ := fields["title"].(string)
	if title == "" {
		s.propValidatorDrift("goal", "title")
		return "", fmt.Errorf("title is required for goal")
	}
	description, _ := fields["description"].(string)
	quarter, _ := fields["quarter"].(string)

	var areaID *uuid.UUID
	if v, ok := fields["area_id"].(string); ok {
		id, err := uuid.Parse(v)
		if err == nil {
			areaID = &id
		}
	}

	var deadline *time.Time
	if v, ok := fields["deadline"].(string); ok && v != "" {
		t, err := time.Parse(time.DateOnly, v)
		if err == nil {
			deadline = &t
		}
	}

	var quarterPtr *string
	if quarter != "" {
		quarterPtr = &quarter
	}

	var row *goal.Goal
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		row, err = goal.NewStore(tx).CreateGoal(ctx, title, description, "in_progress", areaID, quarterPtr, deadline)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("creating goal: %w", err)
	}
	return row.ID.String(), nil
}

func (s *Server) commitProject(ctx context.Context, fields map[string]any) (string, error) {
	title, _ := fields["title"].(string)
	slug, _ := fields["slug"].(string)
	description, _ := fields["description"].(string)

	if title == "" {
		s.propValidatorDrift("project", "title")
		return "", fmt.Errorf("title is required for project")
	}
	if slug == "" {
		s.propValidatorDrift("project", "slug")
		return "", fmt.Errorf("slug is required for project")
	}

	var goalID, areaID *uuid.UUID
	if v, ok := fields["goal_id"].(string); ok {
		if id, err := uuid.Parse(v); err == nil {
			goalID = &id
		}
	}
	if v, ok := fields["area_id"].(string); ok {
		if id, err := uuid.Parse(v); err == nil {
			areaID = &id
		}
	}

	var p *project.Project
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		p, err = project.NewStore(tx).CreateProject(ctx, &project.CreateParams{
			Slug:        slug,
			Title:       title,
			Description: description,
			Status:      project.StatusPlanned,
			GoalID:      goalID,
			AreaID:      areaID,
		})
		return err
	})
	if err != nil {
		return "", fmt.Errorf("creating project: %w", err)
	}

	return p.ID.String(), nil
}

func (s *Server) commitMilestone(ctx context.Context, fields map[string]any) (string, error) {
	title, _ := fields["title"].(string)
	if title == "" {
		s.propValidatorDrift("milestone", "title")
		return "", fmt.Errorf("title is required for milestone")
	}
	description, _ := fields["description"].(string)

	var goalID uuid.UUID
	if v, ok := fields["goal_id"].(string); ok {
		var err error
		goalID, err = uuid.Parse(v)
		if err != nil {
			return "", fmt.Errorf("invalid goal_id: %w", err)
		}
	} else {
		s.propValidatorDrift("milestone", "goal_id")
		return "", fmt.Errorf("goal_id is required for milestone")
	}

	var deadline *time.Time
	if v, ok := fields["target_deadline"].(string); ok && v != "" {
		t, err := time.Parse(time.DateOnly, v)
		if err == nil {
			deadline = &t
		}
	}

	var row *goal.Milestone
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		row, err = goal.NewStore(tx).CreateMilestone(ctx, goalID, title, description, deadline)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("creating milestone: %w", err)
	}
	return row.ID.String(), nil
}

func (s *Server) commitHypothesis(ctx context.Context, fields map[string]any) (string, error) {
	claim, _ := fields["claim"].(string)
	invalidation, _ := fields["invalidation_condition"].(string)
	content, _ := fields["content"].(string)

	if claim == "" {
		s.propValidatorDrift("hypothesis", "claim")
		return "", fmt.Errorf("claim is required for hypothesis")
	}
	if invalidation == "" {
		s.propValidatorDrift("hypothesis", "invalidation_condition")
		return "", fmt.Errorf("invalidation_condition is required for hypothesis")
	}
	if content == "" {
		s.propValidatorDrift("hypothesis", "content")
		return "", fmt.Errorf("content is required for hypothesis")
	}

	var metadata json.RawMessage
	if m, ok := fields["metadata"]; ok {
		metadata, _ = json.Marshal(m)
	}

	rec, err := s.hypotheses.Create(ctx, &hypothesis.CreateParams{
		CreatedBy:             s.callerIdentity(ctx),
		Content:               content,
		Claim:                 claim,
		InvalidationCondition: invalidation,
		Metadata:              metadata,
		ObservedDate:          s.today(),
	})
	if err != nil {
		return "", fmt.Errorf("creating hypothesis: %w", err)
	}
	return rec.ID.String(), nil
}

// resolveLearningDomainFields validates a proposed learning_domain before
// the token is signed. Structural errors (missing or malformed slug/name,
// duplicate slug) reject the proposal. The table only has slug + name +
// active + canonical_writeup_kind; the input contract removed the
// description field rather than accept it and silently drop it.
//
//nolint:unparam // uniform (warnings, err) signature with sibling resolve*Fields
func (s *Server) resolveLearningDomainFields(ctx context.Context, f map[string]any) (warnings []string, err error) {
	slug, _ := f["slug"].(string)
	if slug == "" {
		return nil, fmt.Errorf("slug is required for learning_domain")
	}
	if err := validateSlug("learning_domain slug", slug); err != nil {
		return nil, err
	}
	name, _ := f["name"].(string)
	if name == "" {
		return nil, fmt.Errorf("name is required for learning_domain")
	}
	exists, xErr := s.learn.DomainExists(ctx, slug)
	if xErr != nil {
		return nil, fmt.Errorf("checking domain existence: %w", xErr)
	}
	if exists {
		return nil, fmt.Errorf("learning_domain %q already exists — no action needed", slug)
	}
	return nil, nil
}

func (s *Server) commitLearningDomain(ctx context.Context, fields map[string]any) (string, error) {
	slug, _ := fields["slug"].(string)
	if slug == "" {
		s.propValidatorDrift("learning_domain", "slug")
		return "", fmt.Errorf("slug is required for learning_domain")
	}
	name, _ := fields["name"].(string)
	if name == "" {
		s.propValidatorDrift("learning_domain", "name")
		return "", fmt.Errorf("name is required for learning_domain")
	}
	var d *learning.Domain
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		d, err = s.learn.WithTx(tx).CreateDomain(ctx, slug, name)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("creating learning_domain: %w", err)
	}
	return d.Slug, nil
}

func (s *Server) resolveLearningPlanFields(ctx context.Context, f map[string]any) (warnings []string, err error) {
	if title, ok := f["title"].(string); !ok || title == "" {
		return nil, fmt.Errorf("title is required for learning_plan")
	}
	if domain, ok := f["domain"].(string); !ok || domain == "" {
		return nil, fmt.Errorf("domain is required for learning_plan")
	}
	// Resolve goal_title → goal_id. Goal is optional for a plan — a missing
	// or unresolvable reference is informational.
	if goalTitle, ok := f["goal_title"].(string); ok && goalTitle != "" {
		if g, gErr := s.goals.GoalByTitle(ctx, goalTitle); gErr == nil {
			f["goal_id"] = g.ID.String()
		} else {
			warnings = append(warnings, fmt.Sprintf("goal %q not found — plan will have no goal", goalTitle))
		}
		delete(f, "goal_title")
	}
	return warnings, nil
}

func (s *Server) commitLearningPlan(ctx context.Context, fields map[string]any) (string, error) {
	title, _ := fields["title"].(string)
	description, _ := fields["description"].(string)
	domain, _ := fields["domain"].(string)

	if title == "" {
		s.propValidatorDrift("learning_plan", "title")
		return "", fmt.Errorf("title is required for learning_plan")
	}
	if domain == "" {
		s.propValidatorDrift("learning_plan", "domain")
		return "", fmt.Errorf("domain is required for learning_plan")
	}

	var goalID *uuid.UUID
	if v, ok := fields["goal_id"].(string); ok {
		if id, err := uuid.Parse(v); err == nil {
			goalID = &id
		}
	}

	var targetCount *int32
	if v, ok := fields["target_count"].(float64); ok && v > 0 && v <= 100000 {
		tc := int32(v) // #nosec G115 — bounded above
		targetCount = &tc
	}

	var planConfig json.RawMessage
	if v, ok := fields["plan_config"]; ok {
		planConfig, _ = json.Marshal(v)
	}

	createdBy := s.callerIdentity(ctx)

	p, err := s.plans.CreatePlan(ctx, &plan.CreatePlanParams{
		Title:       title,
		Description: description,
		Domain:      domain,
		GoalID:      goalID,
		TargetCount: targetCount,
		PlanConfig:  planConfig,
		CreatedBy:   createdBy,
	})
	if err != nil {
		return "", fmt.Errorf("creating learning plan: %w", err)
	}
	return p.ID.String(), nil
}
