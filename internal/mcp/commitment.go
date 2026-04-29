// commitment.go holds the two-phase commitment MCP tools:
// propose_commitment and commit_proposal. This is the approved pattern
// for any entity that requires explicit human endorsement — goal,
// project, milestone, hypothesis, learning_plan, directive. See
// .claude/rules/mcp-decision-policy.md §8 for the proposal-first
// matrix.
//
// Why a multiplexer here but flat tools elsewhere (content):
//   - All commitment types share the same workflow (propose → preview
//     → commit) and the same proposal-token plumbing.
//   - Action set is fixed (the Type discriminator is closed).
//   - Splitting would duplicate the proposal-token validator six times.
//
// The HMAC signing/verification lives in proposal.go. This file owns
// per-Type field validation and the commit branch that turns a
// verified token into a domain entity insert.

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/agent/task"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/learning/hypothesis"
	"github.com/Koopa0/koopa/internal/learning/plan"
	"github.com/Koopa0/koopa/internal/project"
)

// learningDomainSlugPattern mirrors the CHECK constraint on
// learning_domains.slug at migrations/001:1519. Validating client-side lets
// us return a specific error instead of a generic CheckViolation from PG.
var learningDomainSlugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// --- propose_commitment ---

// ProposeCommitmentInput is the input for the propose_commitment tool.
type ProposeCommitmentInput struct {
	Type   string         `json:"type" jsonschema:"required" jsonschema_description:"Entity type: goal, project, milestone, directive, hypothesis, learning_plan"`
	Fields map[string]any `json:"fields" jsonschema:"required" jsonschema_description:"Type-specific fields"`
}

// ProposeCommitmentOutput is the output of the propose_commitment tool.
type ProposeCommitmentOutput struct {
	Type          string         `json:"type"`
	Preview       map[string]any `json:"preview"`
	Warnings      []string       `json:"warnings"`
	ProposalToken string         `json:"proposal_token"`
}

// proposeCommitment is the Wave-1 multiplexer. Deprecated 2026-04-24 in
// favor of the per-type flat propose_* tools. Shim forwards to the typed
// handler path via proposeEntity, logs a deprecation warning, and
// prepends a caller-visible deprecation note to Warnings. Scheduled
// removal: 2026-05-08 (tracked in .agents/shim-removal-checklist-2026-05-08.md).
func (s *Server) proposeCommitment(ctx context.Context, _ *mcp.CallToolRequest, input ProposeCommitmentInput) (*mcp.CallToolResult, ProposeCommitmentOutput, error) {
	s.logger.Warn("propose_commitment is deprecated — use propose_<type> directly",
		"caller", s.callerIdentity(ctx),
		"type", input.Type,
		"sunset", "2026-05-08",
	)
	out, err := s.proposeEntity(ctx, input.Type, input.Fields)
	if err != nil {
		return nil, ProposeCommitmentOutput{}, err
	}
	out.Warnings = append([]string{
		"propose_commitment is deprecated — use propose_" + input.Type + " directly. Removal scheduled 2026-05-08.",
	}, out.Warnings...)
	return nil, out, nil
}

// proposeEntity is the internal workhorse shared by the deprecated
// propose_commitment shim and the seven flat propose_* tools. Centralizes
// the type-validate → resolve-fields → sign-proposal dance so each
// typed handler stays small.
//
// The 'type' parameter comes from the tool call site (each flat tool
// knows its own type) or from the shim's input.Type field. Fields is
// the map form resolveProposalFields accepts — flat tools pack their
// typed input into this shape before calling through.
func (s *Server) proposeEntity(ctx context.Context, entityType string, fields map[string]any) (ProposeCommitmentOutput, error) {
	switch entityType {
	case "goal", "project", "milestone", "directive", "hypothesis", "learning_plan", "learning_domain":
		// valid
	default:
		return ProposeCommitmentOutput{}, fmt.Errorf("invalid type %q (valid: goal, project, milestone, directive, hypothesis, learning_plan, learning_domain)", entityType)
	}

	resolved, warnings, err := s.resolveProposalFields(ctx, entityType, fields)
	if err != nil {
		return ProposeCommitmentOutput{}, fmt.Errorf("proposal rejected: %w", err)
	}

	token, err := signProposal(s.proposalSecret, entityType, resolved)
	if err != nil {
		return ProposeCommitmentOutput{}, fmt.Errorf("signing proposal: %w", err)
	}

	s.logger.Info("propose_commitment", "type", entityType)
	return ProposeCommitmentOutput{
		Type:          entityType,
		Preview:       resolved,
		Warnings:      warnings,
		ProposalToken: token,
	}, nil
}

// resolveProposalFields validates and resolves references in proposal fields.
// Returns err when a required field is missing or fails structural validation;
// propose_commitment must NOT sign a token in that case. Warnings communicate
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
	case "directive":
		warnings, err = s.resolveDirectiveFields(ctx, resolved)
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

//nolint:unparam // uniform (warnings, err) signature with sibling resolve*Fields; current directive rules produce only hard errors but future rules may warn
func (s *Server) resolveDirectiveFields(ctx context.Context, f map[string]any) (warnings []string, err error) {
	if _, ok := f["source"]; !ok {
		f["source"] = s.callerIdentity(ctx)
	}
	if target, ok := f["target"].(string); !ok || target == "" {
		return nil, fmt.Errorf("target is required for directive")
	}
	// priority must match the tasks.priority CHECK vocabulary (high | medium | low).
	// No P0/P1/P2 alias — forcing callers to use the schema's single scale avoids
	// split-language queries where the same column carries two meanings.
	if raw, ok := f["priority"]; ok {
		p, isStr := raw.(string)
		if !isStr {
			return nil, fmt.Errorf("priority must be a string (one of: high, medium, low)")
		}
		if !isValidTaskPriority(p) {
			return nil, fmt.Errorf("priority must be one of: high, medium, low (got %q)", p)
		}
	} else {
		f["priority"] = "medium"
	}
	// request_parts is the directive payload — a JSON array of a2a.Part
	// objects that becomes the initial task_messages row (role=request).
	// Hand-rolling the shape is forbidden; LLM clients pass raw Part
	// objects and the task store parses through a2a-go at the boundary.
	if _, ok := f["request_parts"]; !ok {
		return nil, fmt.Errorf(`request_parts is required for directive (array of a2a.Part: [{"text":"..."}] or [{"data":{...}}])`)
	}
	// Title is auto-extracted from request_parts[0].text. The typed
	// proposeDirective handler does this up front so unauthorized callers
	// fail fast on a strict shape; the deprecated propose_commitment
	// shim doesn't, so we run the extraction here if it didn't.
	if title, ok := f["title"].(string); !ok || strings.TrimSpace(title) == "" {
		rawParts, perr := extractRawPartsField(f, "request_parts")
		if perr != nil {
			return nil, fmt.Errorf("extracting title: %w", perr)
		}
		extracted, perr := extractTitleFromFirstTextPart(rawParts)
		if perr != nil {
			return nil, fmt.Errorf("extracting title: %w", perr)
		}
		f["title"] = extracted
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
	ProposalToken string         `json:"proposal_token" jsonschema:"required" jsonschema_description:"Token from propose_commitment"`
	Modifications map[string]any `json:"modifications,omitempty" jsonschema_description:"Optional field overrides before commit"`
}

// CommitProposalOutput is the output of the commit_proposal tool.
type CommitProposalOutput struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Committed bool   `json:"committed"`
}

func (s *Server) commitProposal(ctx context.Context, _ *mcp.CallToolRequest, input CommitProposalInput) (*mcp.CallToolResult, CommitProposalOutput, error) {
	payload, err := verifyProposal(s.proposalSecret, input.ProposalToken)
	if err != nil {
		return nil, CommitProposalOutput{}, fmt.Errorf("invalid proposal: %w", err)
	}

	// Apply modifications.
	fields := payload.Fields
	for k, v := range input.Modifications {
		fields[k] = v
	}

	id, err := s.commitEntity(ctx, payload.Type, fields)
	if err != nil {
		return nil, CommitProposalOutput{}, err
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
	case "directive":
		return s.commitDirective(ctx, fields)
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

	_ = goalID // goal/area linking via project update — not supported in CreateParams yet
	_ = areaID

	var p *project.Project
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		p, err = project.NewStore(tx).CreateProject(ctx, &project.CreateParams{
			Slug:        slug,
			Title:       title,
			Description: description,
			Status:      project.StatusPlanned,
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

func (s *Server) commitDirective(ctx context.Context, fields map[string]any) (string, error) {
	source, _ := fields["source"].(string)
	target, _ := fields["target"].(string)
	priority, _ := fields["priority"].(string)

	if source == "" {
		s.propValidatorDrift("directive", "source")
		return "", fmt.Errorf("source is required for directive")
	}
	if target == "" {
		s.propValidatorDrift("directive", "target")
		return "", fmt.Errorf("target is required for directive")
	}
	// Defensive re-check — resolveDirectiveFields already validated this at
	// propose time, but a token carrying a field that somehow bypassed it
	// (validator drift) must not reach the DB.
	if priority == "" {
		priority = "medium"
	} else if !isValidTaskPriority(priority) {
		s.propValidatorDrift("directive", "priority")
		return "", fmt.Errorf("priority must be one of: high, medium, low (got %q)", priority)
	}

	rawParts, err := extractRawPartsField(fields, "request_parts")
	if err != nil {
		return "", fmt.Errorf("commitDirective: %w", err)
	}
	requestParts, err := parseA2AParts(rawParts)
	if err != nil {
		return "", fmt.Errorf("commitDirective: request_parts: %w", err)
	}

	title, ok := fields["title"].(string)
	if !ok || strings.TrimSpace(title) == "" {
		s.propValidatorDrift("directive", "title")
		return "", fmt.Errorf("commitDirective: title is missing or empty (validator drift — propose_directive should have extracted it from request_parts[0].text)")
	}

	var metadata json.RawMessage
	if m, ok := fields["metadata"]; ok {
		metadata, _ = json.Marshal(m)
	}

	caller := agent.Name(s.callerIdentity(ctx))
	auth, err := agent.Authorize(ctx, s.registry, caller, agent.ActionSubmitTask)
	if err != nil {
		return "", fmt.Errorf("commitDirective: %w", err)
	}

	var t *task.Task
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		t, err = s.tasks.WithTx(tx).Submit(ctx, auth, &task.SubmitInput{
			Source:       source,
			Target:       target,
			Title:        title,
			Priority:     &priority,
			RequestParts: requestParts,
			Metadata:     metadata,
		})
		return err
	})
	if err != nil {
		return "", fmt.Errorf("commitDirective: %w", err)
	}
	return t.ID.String(), nil
}

// directiveTitleMaxRunes caps the auto-extracted directive title at a
// length that fits the morning_context summary view without truncation
// in transit. Inputs longer than this get rune-truncated with an
// ellipsis suffix; the full text remains in request_parts[0].text.
const directiveTitleMaxRunes = 200

// extractTitleFromFirstTextPart returns the title to attach to a
// directive task. The contract is strict: the first request_part MUST
// be a text part with non-empty text after trim. Anything else
// (data-only first part, missing parts, malformed JSON, blank text) is
// rejected at propose time with a 422-style error so the caller learns
// the invariant before the proposal token is ever signed.
//
// Long titles are rune-truncated to directiveTitleMaxRunes and suffixed
// with "…" so the original semantics survives in request_parts.
func extractTitleFromFirstTextPart(parts []json.RawMessage) (string, error) {
	if len(parts) == 0 {
		return "", fmt.Errorf("request_parts is empty; first part must be a text part with non-empty text")
	}
	var first map[string]any
	if err := json.Unmarshal(parts[0], &first); err != nil {
		return "", fmt.Errorf("request_parts[0] is not a valid JSON object: %w", err)
	}
	rawText, ok := first["text"]
	if !ok {
		keys := make([]string, 0, len(first))
		for k := range first {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return "", fmt.Errorf("request_parts[0] must be a text part (have key %q with string value); got keys %v", "text", keys)
	}
	txt, ok := rawText.(string)
	if !ok {
		return "", fmt.Errorf("request_parts[0].text must be a string; got %T", rawText)
	}
	txt = strings.TrimSpace(txt)
	if txt == "" {
		return "", fmt.Errorf("request_parts[0].text is empty after trim; provide a meaningful first sentence — it becomes the directive title")
	}
	runes := []rune(txt)
	if len(runes) > directiveTitleMaxRunes {
		txt = string(runes[:directiveTitleMaxRunes]) + "…"
	}
	return txt, nil
}

// extractRawPartsField reads a `fields[key]` that should be an array of
// JSON objects (each an a2a.Part), returning them as []json.RawMessage
// ready to feed into parseA2AParts. Accepts both the typed case (already
// []json.RawMessage) and the untyped case ([]any of map[string]any
// proposals unmarshaled from the MCP tool schema).
func extractRawPartsField(fields map[string]any, key string) ([]json.RawMessage, error) {
	raw, ok := fields[key]
	if !ok {
		return nil, fmt.Errorf("%s is required", key)
	}
	switch v := raw.(type) {
	case []json.RawMessage:
		return v, nil
	case []any:
		out := make([]json.RawMessage, 0, len(v))
		for i, elem := range v {
			b, err := json.Marshal(elem)
			if err != nil {
				return nil, fmt.Errorf("%s[%d]: %w", key, i, err)
			}
			out = append(out, b)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s: want array of a2a.Part objects, got %T", key, raw)
	}
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
	return fmt.Sprintf("%d", rec.ID), nil
}

// resolveLearningDomainFields validates a proposed learning_domain before the
// token is signed. Structural errors (missing or malformed slug/name,
// duplicate slug) reject the proposal; unknown fields like description —
// which the table lacks — surface as warnings so a caller carrying extra
// metadata does not lose data silently.
func (s *Server) resolveLearningDomainFields(ctx context.Context, f map[string]any) (warnings []string, err error) {
	slug, _ := f["slug"].(string)
	if slug == "" {
		return nil, fmt.Errorf("slug is required for learning_domain")
	}
	if !learningDomainSlugPattern.MatchString(slug) {
		return nil, fmt.Errorf("invalid slug %q: must be lowercase kebab-case starting with a letter (pattern: %s)", slug, learningDomainSlugPattern.String())
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
	if _, ok := f["description"]; ok {
		warnings = append(warnings, "learning_domains has no description column; field will be ignored")
	}
	return warnings, nil
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
