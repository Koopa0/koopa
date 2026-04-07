package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/directive"
	"github.com/Koopa0/koopa0.dev/internal/insight"
	"github.com/Koopa0/koopa0.dev/internal/project"
)

// --- propose_commitment ---

// ProposeCommitmentInput is the input for the propose_commitment tool.
type ProposeCommitmentInput struct {
	Type   string         `json:"type" jsonschema:"required" jsonschema_description:"Entity type: goal, project, milestone, directive, insight"`
	Fields map[string]any `json:"fields" jsonschema:"required" jsonschema_description:"Type-specific fields"`
}

// ProposeCommitmentOutput is the output of the propose_commitment tool.
type ProposeCommitmentOutput struct {
	Type          string         `json:"type"`
	Preview       map[string]any `json:"preview"`
	Warnings      []string       `json:"warnings"`
	ProposalToken string         `json:"proposal_token"`
}

func (s *Server) proposeCommitment(ctx context.Context, _ *sdkmcp.CallToolRequest, input ProposeCommitmentInput) (*sdkmcp.CallToolResult, ProposeCommitmentOutput, error) {
	switch input.Type {
	case "goal", "project", "milestone", "directive", "insight":
		// valid
	default:
		return nil, ProposeCommitmentOutput{}, fmt.Errorf("invalid type %q (valid: goal, project, milestone, directive, insight)", input.Type)
	}

	// Resolve references and validate fields.
	resolved, warnings := s.resolveProposalFields(ctx, input.Type, input.Fields)

	// Sign the proposal token.
	token, err := signProposal(s.proposalSecret, input.Type, resolved)
	if err != nil {
		return nil, ProposeCommitmentOutput{}, fmt.Errorf("signing proposal: %w", err)
	}

	s.logger.Info("propose_commitment", "type", input.Type)
	return nil, ProposeCommitmentOutput{
		Type:          input.Type,
		Preview:       resolved,
		Warnings:      warnings,
		ProposalToken: token,
	}, nil
}

// resolveProposalFields validates and resolves references in proposal fields.
func (s *Server) resolveProposalFields(ctx context.Context, entityType string, fields map[string]any) (resolved map[string]any, warnings []string) {
	resolved = make(map[string]any, len(fields))
	for k, v := range fields {
		resolved[k] = v
	}

	switch entityType {
	case "goal":
		warnings = resolveGoalFields(resolved)
	case "project":
		warnings = s.resolveProjectFields(ctx, resolved)
	case "milestone":
		warnings = s.resolveMilestoneFields(ctx, resolved)
	case "directive":
		warnings = s.resolveDirectiveFields(resolved)
	case "insight":
		warnings = resolveInsightFields(resolved)
	}
	return resolved, warnings
}

func resolveGoalFields(f map[string]any) []string {
	var w []string
	if _, ok := f["title"]; !ok {
		w = append(w, "title is required for goal")
	}
	if _, ok := f["area_id"]; !ok {
		w = append(w, "no area_id specified — goal will be unscoped")
	}
	return w
}

func (s *Server) resolveProjectFields(ctx context.Context, f map[string]any) []string {
	var w []string
	if _, ok := f["title"]; !ok {
		w = append(w, "title is required for project")
	}
	if _, ok := f["slug"]; !ok {
		w = append(w, "slug is required for project")
	}
	if goalTitle, ok := f["goal_title"].(string); ok && goalTitle != "" {
		if g, err := s.goals.GoalByTitle(ctx, goalTitle); err == nil {
			f["goal_id"] = g.ID.String()
		} else {
			w = append(w, fmt.Sprintf("goal %q not found", goalTitle))
		}
		delete(f, "goal_title")
	}
	return w
}

func (s *Server) resolveMilestoneFields(ctx context.Context, f map[string]any) []string {
	var w []string
	if _, ok := f["title"]; !ok {
		w = append(w, "title is required for milestone")
	}
	if goalTitle, ok := f["goal_title"].(string); ok && goalTitle != "" {
		if g, err := s.goals.GoalByTitle(ctx, goalTitle); err == nil {
			f["goal_id"] = g.ID.String()
		} else {
			w = append(w, fmt.Sprintf("goal %q not found — milestone must belong to a goal", goalTitle))
		}
		delete(f, "goal_title")
	} else if _, ok := f["goal_id"]; !ok {
		w = append(w, "goal_title or goal_id is required for milestone")
	}
	return w
}

func (s *Server) resolveDirectiveFields(f map[string]any) []string {
	var w []string
	if _, ok := f["source"]; !ok {
		f["source"] = s.participant
	}
	if _, ok := f["target"]; !ok {
		w = append(w, "target is required for directive")
	}
	if _, ok := f["priority"]; !ok {
		f["priority"] = "p1"
	}
	if _, ok := f["content"]; !ok {
		w = append(w, "content is required for directive")
	}
	return w
}

func resolveInsightFields(f map[string]any) []string {
	var w []string
	if _, ok := f["hypothesis"]; !ok {
		w = append(w, "hypothesis is required for insight")
	}
	if _, ok := f["invalidation_condition"]; !ok {
		w = append(w, "invalidation_condition is required for insight")
	}
	if _, ok := f["content"]; !ok {
		w = append(w, "content is required for insight")
	}
	return w
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

func (s *Server) commitProposal(ctx context.Context, _ *sdkmcp.CallToolRequest, input CommitProposalInput) (*sdkmcp.CallToolResult, CommitProposalOutput, error) {
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
	case "insight":
		return s.commitInsight(ctx, fields)
	default:
		return "", fmt.Errorf("unknown entity type: %s", entityType)
	}
}

func (s *Server) commitGoal(ctx context.Context, fields map[string]any) (string, error) {
	title, _ := fields["title"].(string)
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

	row, err := s.goals.CreateGoal(ctx, title, description, "not-started", areaID, quarterPtr, deadline)
	if err != nil {
		return "", fmt.Errorf("creating goal: %w", err)
	}
	return row.ID.String(), nil
}

func (s *Server) commitProject(ctx context.Context, fields map[string]any) (string, error) {
	title, _ := fields["title"].(string)
	slug, _ := fields["slug"].(string)
	description, _ := fields["description"].(string)

	if title == "" || slug == "" {
		return "", fmt.Errorf("title and slug are required for project")
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

	p, err := s.projects.CreateProject(ctx, &project.CreateParams{
		Slug:        slug,
		Title:       title,
		Description: description,
		Status:      project.StatusPlanned,
	})
	if err != nil {
		return "", fmt.Errorf("creating project: %w", err)
	}

	return p.ID.String(), nil
}

func (s *Server) commitMilestone(ctx context.Context, fields map[string]any) (string, error) {
	title, _ := fields["title"].(string)
	description, _ := fields["description"].(string)

	var goalID uuid.UUID
	if v, ok := fields["goal_id"].(string); ok {
		var err error
		goalID, err = uuid.Parse(v)
		if err != nil {
			return "", fmt.Errorf("invalid goal_id: %w", err)
		}
	} else {
		return "", fmt.Errorf("goal_id is required for milestone")
	}

	var deadline *time.Time
	if v, ok := fields["target_deadline"].(string); ok && v != "" {
		t, err := time.Parse(time.DateOnly, v)
		if err == nil {
			deadline = &t
		}
	}

	row, err := s.goals.CreateMilestone(ctx, goalID, title, description, deadline)
	if err != nil {
		return "", fmt.Errorf("creating milestone: %w", err)
	}
	return row.ID.String(), nil
}

func (s *Server) commitDirective(ctx context.Context, fields map[string]any) (string, error) {
	source, _ := fields["source"].(string)
	target, _ := fields["target"].(string)
	priority, _ := fields["priority"].(string)
	content, _ := fields["content"].(string)

	if source == "" || target == "" || content == "" {
		return "", fmt.Errorf("source, target, and content are required for directive")
	}
	if priority == "" {
		priority = "p1"
	}

	var metadata json.RawMessage
	if m, ok := fields["metadata"]; ok {
		metadata, _ = json.Marshal(m)
	}

	d, err := s.directives.Create(ctx, &directive.CreateParams{
		Source:     source,
		Target:     target,
		Priority:   priority,
		Content:    content,
		Metadata:   metadata,
		IssuedDate: s.today(),
	})
	if err != nil {
		return "", fmt.Errorf("creating directive: %w", err)
	}
	return fmt.Sprintf("%d", d.ID), nil
}

func (s *Server) commitInsight(ctx context.Context, fields map[string]any) (string, error) {
	hypothesis, _ := fields["hypothesis"].(string)
	invalidation, _ := fields["invalidation_condition"].(string)
	content, _ := fields["content"].(string)

	if hypothesis == "" || invalidation == "" || content == "" {
		return "", fmt.Errorf("hypothesis, invalidation_condition, and content are required for insight")
	}

	var metadata json.RawMessage
	if m, ok := fields["metadata"]; ok {
		metadata, _ = json.Marshal(m)
	}

	ins, err := s.insights.Create(ctx, &insight.CreateParams{
		Source:                s.participant,
		Content:               content,
		Hypothesis:            hypothesis,
		InvalidationCondition: invalidation,
		Metadata:              metadata,
		ObservedDate:          s.today(),
	})
	if err != nil {
		return "", fmt.Errorf("creating insight: %w", err)
	}
	return fmt.Sprintf("%d", ins.ID), nil
}
