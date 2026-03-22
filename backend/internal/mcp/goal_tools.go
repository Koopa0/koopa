package mcpserver

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GoalProgressInput is the input for the get_goal_progress tool.
type GoalProgressInput struct {
	Days int `json:"days,omitempty" jsonschema_description:"lookback period in days for task counting. Default 30, max 90."`
}

// GoalProgressOutput shows progress toward each active goal.
type GoalProgressOutput struct {
	Goals []goalProgressDetail `json:"goals"`
}

type goalProgressDetail struct {
	Title                 string   `json:"title"`
	Status                string   `json:"status"`
	Area                  string   `json:"area,omitempty"`
	Deadline              string   `json:"deadline,omitempty"`
	DaysRemaining         int      `json:"days_remaining,omitempty"`
	RelatedProjects       []string `json:"related_projects"`
	RelatedTasksCompleted int64    `json:"related_tasks_completed"`
	WeeklyTaskRate        float64  `json:"weekly_task_rate"`
	OnTrackAssessment     string   `json:"on_track_assessment"`
}

func (s *Server) getGoalProgress(ctx context.Context, _ *mcp.CallToolRequest, input GoalProgressInput) (*mcp.CallToolResult, GoalProgressOutput, error) {
	days := clamp(input.Days, 7, 90, 30)
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	since := today.AddDate(0, 0, -days)

	// Fetch all data sources
	goals, err := s.goals.Goals(ctx)
	if err != nil {
		return nil, GoalProgressOutput{}, err
	}

	projects, projErr := s.projects.ActiveProjects(ctx)
	if projErr != nil {
		s.logger.Error("goal_progress: active projects", "error", projErr)
	}

	byProject, taskErr := s.tasks.CompletedByProjectSince(ctx, since)
	if taskErr != nil {
		s.logger.Error("goal_progress: completed by project", "error", taskErr)
	}

	// Build area → projects mapping
	projectsByArea := make(map[string][]string)
	for _, p := range projects {
		if p.Area != "" {
			projectsByArea[p.Area] = append(projectsByArea[p.Area], p.Title)
		}
	}

	// Build project → completions mapping
	completionsByProject := make(map[string]int64)
	for _, p := range byProject {
		completionsByProject[p.ProjectTitle] = p.Completed
	}

	// Build goal progress
	result := make([]goalProgressDetail, 0)
	for _, g := range goals {
		if string(g.Status) == "done" || string(g.Status) == "abandoned" {
			continue
		}

		gp := goalProgressDetail{
			Title:           g.Title,
			Status:          string(g.Status),
			Area:            g.Area,
			RelatedProjects: projectsByArea[g.Area],
		}
		if gp.RelatedProjects == nil {
			gp.RelatedProjects = []string{}
		}

		if g.Deadline != nil {
			gp.Deadline = g.Deadline.Format(time.DateOnly)
			gp.DaysRemaining = int(g.Deadline.Sub(today).Hours() / 24)
		}

		// Sum completions for related projects
		for _, pTitle := range gp.RelatedProjects {
			gp.RelatedTasksCompleted += completionsByProject[pTitle]
		}

		// Weekly task rate
		weeks := float64(days) / 7.0
		if weeks > 0 {
			gp.WeeklyTaskRate = float64(gp.RelatedTasksCompleted) / weeks
		}

		// On-track assessment
		gp.OnTrackAssessment = "on_track"
		if gp.RelatedTasksCompleted == 0 && gp.DaysRemaining > 0 && gp.DaysRemaining < 60 {
			gp.OnTrackAssessment = "off_track"
		} else if gp.RelatedTasksCompleted == 0 {
			gp.OnTrackAssessment = "at_risk"
		} else if gp.WeeklyTaskRate < 1 && gp.DaysRemaining > 0 && gp.DaysRemaining < 90 {
			gp.OnTrackAssessment = "at_risk"
		}

		result = append(result, gp)
	}

	return nil, GoalProgressOutput{Goals: result}, nil
}
