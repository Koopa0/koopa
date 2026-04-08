package mcp

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/goal"
)

// --- goal_progress ---

// GoalProgressInput is the input for the goal_progress tool.
type GoalProgressInput struct {
	// Phase 2: basic active goals with milestone progress.
	// Future: area filter, status filter, drift analysis.
}

// GoalProgressOutput is the output of the goal_progress tool.
type GoalProgressOutput struct {
	Goals []goal.ActiveGoalSummary `json:"goals"`
	Total int                      `json:"total"`
}

func (s *Server) goalProgress(ctx context.Context, _ *mcp.CallToolRequest, _ GoalProgressInput) (*mcp.CallToolResult, GoalProgressOutput, error) {
	goals, err := s.goals.ActiveGoals(ctx)
	if err != nil {
		return nil, GoalProgressOutput{}, err
	}

	return nil, GoalProgressOutput{
		Goals: goals,
		Total: len(goals),
	}, nil
}
