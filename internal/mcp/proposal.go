// Copyright 2026 Koopa. All rights reserved.

// proposal.go holds the agent proposal tools: propose_area, propose_goal,
// propose_project, and propose_content. propose_area, propose_goal, and
// propose_project each write an INERT draft (status=proposed) that the owner
// activates or rejects in the admin UI; propose_content pushes a finished
// piece into the review queue (status=review). The tools exist to remove
// Koopa's authoring-from-blank paralysis: an agent that has surfaced a theme,
// objective, project, or piece in conversation can propose it, and Koopa
// decides in triage.
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
// owner was part of — NEVER from a scheduled or autonomous run. A proposal is
// a pull-only, notification-worthy suggestion, not an autonomous write.

package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/project"
)

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
	if goal.ContainsControlChars(input.Name) {
		return nil, ProposeAreaOutput{}, fmt.Errorf("name must not contain control characters")
	}
	if goal.ContainsControlChars(input.Description) {
		return nil, ProposeAreaOutput{}, fmt.Errorf("description must not contain control characters")
	}
	if goal.ContainsControlChars(input.Rationale) {
		return nil, ProposeAreaOutput{}, fmt.Errorf("rationale must not contain control characters")
	}
	slug := goal.DeriveSlug(input.Name)
	if slug == "" {
		return nil, ProposeAreaOutput{}, fmt.Errorf("name %q must contain at least one letter or number", input.Name)
	}

	var created *goal.ProposedArea
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		var createErr error
		created, createErr = s.goals.WithTx(tx).ProposeArea(ctx, &goal.ProposeAreaParams{
			Slug:        slug,
			Name:        strings.TrimSpace(input.Name),
			Description: input.Description,
			CreatedBy:   s.callerIdentity(ctx),
			Rationale:   nilIfBlank(input.Rationale),
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
	Area        string   `json:"area,omitempty" jsonschema_description:"Area to file the goal under: an existing ACTIVE area's slug/name, OR the slug/name of an area that has been proposed but not yet activated. Omit to leave the goal unclassified."`
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
	if goal.ContainsControlChars(input.Title) {
		return nil, ProposeGoalOutput{}, fmt.Errorf("title must not contain control characters")
	}
	if goal.ContainsControlChars(input.Description) {
		return nil, ProposeGoalOutput{}, fmt.Errorf("description must not contain control characters")
	}
	if goal.ContainsControlChars(input.Rationale) {
		return nil, ProposeGoalOutput{}, fmt.Errorf("rationale must not contain control characters")
	}
	for i, m := range input.Milestones {
		if strings.TrimSpace(m) == "" {
			return nil, ProposeGoalOutput{}, fmt.Errorf("milestone %d is blank; every milestone needs a title", i+1)
		}
		if goal.ContainsControlChars(m) {
			return nil, ProposeGoalOutput{}, fmt.Errorf("milestone %d must not contain control characters", i+1)
		}
	}

	var created *goal.Goal
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		store := s.goals.WithTx(tx)

		// Resolve the area within the tx, matching proposed areas too so a
		// goal can be filed under an area that is proposed but not yet
		// activated (the bundle case). nil area = unclassified.
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
			Rationale:   nilIfBlank(input.Rationale),
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

// --- propose_project ---

// ProposeProjectInput is the input for the propose_project tool. The created
// row always lands in status=proposed — an inert draft: the agent suggests a
// NEW project, only the owner makes it real (activation or rejection live in
// the admin UI, off the MCP surface). EXISTING projects are referenced directly
// via capture_inbox.project; propose_project is for genuinely-new projects only.
type ProposeProjectInput struct {
	As          string `json:"as,omitempty" jsonschema_description:"Self-identification — the agent making this call. Stamped on projects.created_by."`
	Name        string `json:"name" jsonschema:"required" jsonschema_description:"Display name / title of the proposed project (e.g. 'Koopa CLI'). Required and non-blank. The slug is derived from it."`
	Description string `json:"description,omitempty" jsonschema_description:"What this project delivers and what 'done' looks like."`
	Rationale   string `json:"rationale,omitempty" jsonschema_description:"Why this project is worth proposing now — shown to the owner in triage to support the activate/reject decision."`
}

// ProposeProjectOutput is the output of the propose_project tool.
type ProposeProjectOutput struct {
	Project *project.Project `json:"project"`
}

func (s *Server) proposeProject(ctx context.Context, _ *mcp.CallToolRequest, input ProposeProjectInput) (*mcp.CallToolResult, ProposeProjectOutput, error) {
	if err := s.requireRegisteredCaller(ctx, "propose_project"); err != nil {
		return nil, ProposeProjectOutput{}, err
	}
	if strings.TrimSpace(input.Name) == "" {
		return nil, ProposeProjectOutput{}, fmt.Errorf("name is required")
	}
	if goal.ContainsControlChars(input.Name) {
		return nil, ProposeProjectOutput{}, fmt.Errorf("name must not contain control characters")
	}
	if goal.ContainsControlChars(input.Description) {
		return nil, ProposeProjectOutput{}, fmt.Errorf("description must not contain control characters")
	}
	if goal.ContainsControlChars(input.Rationale) {
		return nil, ProposeProjectOutput{}, fmt.Errorf("rationale must not contain control characters")
	}
	slug := goal.DeriveSlug(input.Name)
	if slug == "" {
		return nil, ProposeProjectOutput{}, fmt.Errorf("name %q must contain at least one letter or number", input.Name)
	}

	var created *project.Project
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		var createErr error
		created, createErr = s.projects.WithTx(tx).ProposeProject(ctx, &project.ProposeProjectParams{
			Slug:        slug,
			Title:       strings.TrimSpace(input.Name),
			Description: input.Description,
			CreatedBy:   s.callerIdentity(ctx),
			Rationale:   nilIfBlank(input.Rationale),
		})
		return createErr
	})
	if err != nil {
		if errors.Is(err, project.ErrConflict) {
			return nil, ProposeProjectOutput{}, fmt.Errorf("a project with slug %q already exists", slug)
		}
		if errors.Is(err, project.ErrInvalidInput) {
			return nil, ProposeProjectOutput{}, fmt.Errorf("invalid project input: name must be non-blank and slug url-safe")
		}
		return nil, ProposeProjectOutput{}, fmt.Errorf("proposing project: %w", err)
	}

	s.logger.Info("propose_project", "project_id", created.ID, "slug", created.Slug, "created_by", s.callerIdentity(ctx))
	return nil, ProposeProjectOutput{Project: created}, nil
}

// --- propose_content ---

// ProposeContentInput is the input for the propose_content tool. A registered
// agent (e.g. hermes pushing a finished Obsidian draft) proposes a finished
// content piece; it always lands in status=review with is_public=false — the
// agent CANNOT publish. Koopa reviews it in the admin review queue and
// publishes or rejects.
type ProposeContentInput struct {
	As                string   `json:"as,omitempty" jsonschema_description:"Self-identification — the agent making this call. Stamped on contents.created_by."`
	Title             string   `json:"title" jsonschema:"required" jsonschema_description:"Content title. Required and non-blank. The slug is derived from it when slug is omitted."`
	Type              string   `json:"type" jsonschema:"required" jsonschema_description:"Content type. One of: article, essay, build-log, til, digest."`
	Body              string   `json:"body" jsonschema:"required" jsonschema_description:"The finished content body (Markdown). Required and non-blank — propose_content is for finished drafts, not stubs."`
	Excerpt           string   `json:"excerpt,omitempty" jsonschema_description:"Optional short summary / excerpt shown in listings."`
	Slug              string   `json:"slug,omitempty" jsonschema_description:"Optional URL-safe slug. Derived from title when omitted. Hyphen-separated, no leading/trailing/consecutive hyphens; Unicode letters/numbers allowed."`
	TopicIDs          []string `json:"topic_ids,omitempty" jsonschema_description:"Optional topic UUIDs to associate with the content."`
	ProposalRationale string   `json:"proposal_rationale,omitempty" jsonschema_description:"Why this content is worth proposing now — shown to the owner in the review queue to support the publish/reject decision."`
}

// ProposeContentOutput is the output of the propose_content tool.
type ProposeContentOutput struct {
	Content *content.Content `json:"content"`
}

// validateProposeContent enforces propose_content's client-side input rules
// and returns the resolved content type, slug, and parsed topic ids. Keeping
// the branchy validation here keeps the handler's cyclomatic complexity in
// check (gocyclo). Title/excerpt/rationale are single-line fields (strict
// control-char check); body is multi-line Markdown (prose check permits
// HT/LF/CR). An omitted slug is derived from the title; an all-punctuation
// title yields no slug and is rejected rather than inventing one.
//
//nolint:gocritic // hugeParam: input mirrors the handler's by-value contract
func validateProposeContent(input ProposeContentInput) (content.Type, string, []uuid.UUID, error) {
	if strings.TrimSpace(input.Title) == "" {
		return "", "", nil, fmt.Errorf("title is required")
	}
	if strings.TrimSpace(input.Type) == "" {
		return "", "", nil, fmt.Errorf("type is required")
	}
	if strings.TrimSpace(input.Body) == "" {
		return "", "", nil, fmt.Errorf("body is required")
	}
	contentType := content.Type(input.Type)
	if !contentType.Valid() {
		return "", "", nil, fmt.Errorf("type must be one of: article, essay, build-log, til, digest (got %q)", input.Type)
	}
	if goal.ContainsControlChars(input.Title) {
		return "", "", nil, fmt.Errorf("title must not contain control characters")
	}
	if containsProseControlChars(input.Body) {
		return "", "", nil, fmt.Errorf("body must not contain control characters")
	}
	if goal.ContainsControlChars(input.Excerpt) {
		return "", "", nil, fmt.Errorf("excerpt must not contain control characters")
	}
	if goal.ContainsControlChars(input.ProposalRationale) {
		return "", "", nil, fmt.Errorf("proposal_rationale must not contain control characters")
	}
	if err := content.CheckFieldLengths(&input.Title, &input.Excerpt, &input.Body); err != nil {
		return "", "", nil, err
	}
	if err := content.CheckRationaleLength(input.ProposalRationale); err != nil {
		return "", "", nil, err
	}

	slug := strings.TrimSpace(input.Slug)
	if slug == "" {
		slug = goal.DeriveSlug(input.Title)
	}
	if slug == "" {
		return "", "", nil, fmt.Errorf("title %q must contain at least one letter or number to derive a slug", input.Title)
	}

	topicIDs, err := parseTopicIDs(input.TopicIDs)
	if err != nil {
		return "", "", nil, err
	}
	return contentType, slug, topicIDs, nil
}

//nolint:gocritic // hugeParam: input passed by value per addTool[I,O] generic contract
func (s *Server) proposeContent(ctx context.Context, _ *mcp.CallToolRequest, input ProposeContentInput) (*mcp.CallToolResult, ProposeContentOutput, error) {
	if err := s.requireRegisteredCaller(ctx, "propose_content"); err != nil {
		return nil, ProposeContentOutput{}, err
	}
	contentType, slug, topicIDs, err := validateProposeContent(input)
	if err != nil {
		return nil, ProposeContentOutput{}, err
	}

	caller := s.callerIdentity(ctx)

	var created *content.Content
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		var createErr error
		created, createErr = s.contents.WithTx(tx).CreateContent(ctx, &content.CreateParams{
			Slug:              slug,
			Title:             strings.TrimSpace(input.Title),
			Body:              input.Body,
			Excerpt:           input.Excerpt,
			Type:              contentType,
			Status:            content.StatusReview,
			IsPublic:          false,
			TopicIDs:          topicIDs,
			CreatedBy:         &caller,
			ProposalRationale: nilIfBlank(input.ProposalRationale),
		})
		return createErr
	})
	if err != nil {
		if sc, ok := errors.AsType[*content.SlugConflictError](err); ok {
			return nil, ProposeContentOutput{}, fmt.Errorf("a content with slug %q already exists (id %s); pick a different slug", sc.Slug, sc.ContentID)
		}
		if errors.Is(err, content.ErrConflict) {
			return nil, ProposeContentOutput{}, fmt.Errorf("a content with slug %q already exists", slug)
		}
		if errors.Is(err, content.ErrInvalidInput) {
			return nil, ProposeContentOutput{}, fmt.Errorf("invalid content input: check slug format and topic ids")
		}
		return nil, ProposeContentOutput{}, fmt.Errorf("proposing content: %w", err)
	}

	s.logger.Info("propose_content", "content_id", created.ID, "slug", created.Slug, "type", created.Type, "created_by", caller)
	return nil, ProposeContentOutput{Content: created}, nil
}

// parseTopicIDs converts the string topic ids supplied by an agent into UUIDs,
// rejecting any malformed value as a clean caller error.
func parseTopicIDs(raw []string) ([]uuid.UUID, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	ids := make([]uuid.UUID, 0, len(raw))
	for _, s := range raw {
		id, err := uuid.Parse(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("topic id %q is not a valid uuid", s)
		}
		ids = append(ids, id)
	}
	return ids, nil
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
			return nil, fmt.Errorf("no area matches %q (use an active area or one that has been proposed but not yet activated)", identifier)
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

// nilIfBlank maps an omitted-or-whitespace rationale to nil so it persists as
// SQL NULL (matching proposal_rationale's "NULL for admin/seeded rows"
// semantics), and a real justification to a pointer to the original value.
func nilIfBlank(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}
