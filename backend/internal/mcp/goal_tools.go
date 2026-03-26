package mcpserver

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GoalProgressInput is the input for the get_goal_progress tool.
type GoalProgressInput struct {
	Days   int    `json:"days,omitempty" jsonschema_description:"lookback period in days for task counting. Default 30, max 90."`
	Area   string `json:"area,omitempty" jsonschema_description:"filter goals by area"`
	Status string `json:"status,omitempty" jsonschema_description:"filter goals by status (not-started, in-progress, done, abandoned)"`
}

// GoalProgressOutput shows progress toward each active goal.
type GoalProgressOutput struct {
	Goals []goalProgressDetail `json:"goals"`
}

type goalProgressDetail struct {
	Title                 string   `json:"title"`
	Description           string   `json:"description,omitempty"`
	Status                string   `json:"status"`
	Area                  string   `json:"area,omitempty"`
	Quarter               string   `json:"quarter,omitempty"`
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

	// Use activity events for completion counting — captures recurring task
	// completions that disappear from the tasks table snapshot.
	byProject, taskErr := s.activity.CompletionsByProjectSince(ctx, since)
	if taskErr != nil {
		s.logger.Error("goal_progress: completion events by project", "error", taskErr)
	}

	// Build goal_id → projects mapping (FK-based, not area-based)
	projectsByGoalID := make(map[uuid.UUID][]string)
	for pIdx := range projects {
		p := projects[pIdx]
		if p.GoalID != nil {
			projectsByGoalID[*p.GoalID] = append(projectsByGoalID[*p.GoalID], p.Title)
		}
	}

	// Build project → completions mapping
	completionsByProject := make(map[string]int64)
	for _, p := range byProject {
		completionsByProject[p.ProjectTitle] = p.Completed
	}

	// Build goal progress
	result := make([]goalProgressDetail, 0)
	for gIdx := range goals {
		g := goals[gIdx]
		// By default, exclude done/abandoned. But if caller explicitly
		// filters by status, respect their choice.
		if input.Status == "" && (string(g.Status) == "done" || string(g.Status) == "abandoned") {
			continue
		}
		if input.Area != "" && g.Area != input.Area {
			continue
		}
		if input.Status != "" && string(g.Status) != input.Status {
			continue
		}

		gp := goalProgressDetail{
			Title:           g.Title,
			Description:     g.Description,
			Status:          string(g.Status),
			Area:            g.Area,
			Quarter:         g.Quarter,
			RelatedProjects: projectsByGoalID[g.ID],
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

		gp.OnTrackAssessment = assessOnTrack(gp.RelatedTasksCompleted, gp.WeeklyTaskRate, gp.DaysRemaining)

		result = append(result, gp)
	}

	return nil, GoalProgressOutput{Goals: result}, nil
}

// assessOnTrack determines goal progress status based on task completions and deadline proximity.
// Used by both get_goal_progress and get_weekly_summary for consistent assessment.
func assessOnTrack(tasksCompleted int64, weeklyRate float64, daysRemaining int) string {
	switch {
	case tasksCompleted == 0 && daysRemaining > 0 && daysRemaining < 60:
		return "off_track"
	case tasksCompleted == 0:
		return "at_risk"
	case weeklyRate < 1 && daysRemaining > 0 && daysRemaining < 90:
		return "at_risk"
	default:
		return "on_track"
	}
}
