package mcp

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/project"
)

// --- goal_progress ---

// GoalProgressInput is the input for the goal_progress tool.
type GoalProgressInput struct {
	Status *string `json:"status,omitempty" jsonschema_description:"Filter by goal status (default: in_progress). Use 'all' for all statuses."`
}

// GoalProgressProject is a lightweight project summary within goal progress.
type GoalProgressProject struct {
	Slug           string `json:"slug"`
	Title          string `json:"title"`
	Status         string `json:"status"`
	LastActivityAt string `json:"last_activity_at,omitempty"`
}

// GoalProgressGoal extends ActiveGoalSummary with linked projects.
type GoalProgressGoal struct {
	goal.ActiveGoalSummary
	Projects []GoalProgressProject `json:"projects"`
}

// GoalProgressOutput is the output of the goal_progress tool.
type GoalProgressOutput struct {
	Goals []GoalProgressGoal `json:"goals"`
	Total int                `json:"total"`
}

func (s *Server) goalProgress(ctx context.Context, _ *mcp.CallToolRequest, input GoalProgressInput) (*mcp.CallToolResult, GoalProgressOutput, error) {
	if input.Status != nil && *input.Status != "" && !isValidGoalStatusFilter(*input.Status) {
		return nil, GoalProgressOutput{}, fmt.Errorf("status must be one of: all, not_started, in_progress, done, abandoned, on_hold (got %q)", *input.Status)
	}

	var goals []goal.ActiveGoalSummary
	var err error

	switch {
	case input.Status != nil && *input.Status == "all":
		goals, err = s.goals.GoalsByOptionalStatus(ctx, nil)
	case input.Status != nil && *input.Status != "":
		goals, err = s.goals.GoalsByOptionalStatus(ctx, input.Status)
	default:
		goals, err = s.goals.ActiveGoals(ctx)
	}
	if err != nil {
		return nil, GoalProgressOutput{}, err
	}

	// Collect goal IDs for batch project lookup.
	goalIDs := make([]uuid.UUID, len(goals))
	for i := range goals {
		goalIDs[i] = goals[i].ID
	}

	// Batch fetch projects for all goals.
	var projByGoal map[uuid.UUID][]GoalProgressProject
	if summaries, pErr := s.projects.SummariesByGoalIDs(ctx, goalIDs); pErr == nil {
		projByGoal = groupProjectsByGoal(summaries)
	} else {
		s.logger.Warn("goal_progress: project summaries", "error", pErr)
	}

	result := make([]GoalProgressGoal, len(goals))
	for i := range goals {
		result[i] = GoalProgressGoal{
			ActiveGoalSummary: goals[i],
			Projects:          projByGoal[goals[i].ID],
		}
		if result[i].Projects == nil {
			result[i].Projects = []GoalProgressProject{}
		}
	}

	return nil, GoalProgressOutput{
		Goals: result,
		Total: len(result),
	}, nil
}

func groupProjectsByGoal(summaries []project.ProjectSummary) map[uuid.UUID][]GoalProgressProject {
	m := make(map[uuid.UUID][]GoalProgressProject)
	for i := range summaries {
		s := &summaries[i]
		if s.GoalID == nil {
			continue
		}
		p := GoalProgressProject{
			Slug:   s.Slug,
			Title:  s.Title,
			Status: string(s.Status),
		}
		if s.LastActivityAt != nil {
			p.LastActivityAt = s.LastActivityAt.Format("2006-01-02")
		}
		m[*s.GoalID] = append(m[*s.GoalID], p)
	}
	return m
}
