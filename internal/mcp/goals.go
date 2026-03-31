package mcp

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/Koopa0/koopa0.dev/internal/goal"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GoalProgressInput is the input for the goal_progress tool.
type GoalProgressInput struct {
	Days         int    `json:"days,omitempty" jsonschema_description:"lookback period in days for task counting. Default 30, max 90."`
	Area         string `json:"area,omitempty" jsonschema_description:"filter goals by area"`
	Status       string `json:"status,omitempty" jsonschema_description:"filter goals by status (not-started, in-progress, done, abandoned)"`
	IncludeDrift bool   `json:"include_drift,omitempty" jsonschema_description:"include goal-vs-activity drift analysis showing per-area alignment percentages"`
}

// GoalProgressOutput shows progress toward each active goal.
type GoalProgressOutput struct {
	Goals []goalProgressDetail `json:"goals"`
	Drift *driftSummary        `json:"drift,omitempty"`
}

type driftSummary struct {
	Period string          `json:"period"`
	Areas  []driftAreaItem `json:"areas"`
}

type driftAreaItem struct {
	Area         string  `json:"area"`
	ActiveGoals  int     `json:"active_goals"`
	EventCount   int     `json:"event_count"`
	EventPercent float64 `json:"event_percent"`
	GoalPercent  float64 `json:"goal_percent"`
	DriftPercent float64 `json:"drift_percent"`
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

	goals, err := s.goals.Goals(ctx)
	if err != nil {
		return nil, GoalProgressOutput{}, err
	}

	projects, projErr := s.projects.ActiveProjects(ctx)
	if projErr != nil {
		s.logger.Error("goal_progress: active projects", "error", projErr)
	}

	byProject, taskErr := s.activity.CompletionsByProjectSince(ctx, since)
	if taskErr != nil {
		s.logger.Error("goal_progress: completion events by project", "error", taskErr)
	}

	projectsByGoalID := buildProjectsByGoalID(projects)
	completionsByProject := buildCompletionsByProject(byProject)

	result := buildGoalProgressList(goals, input, projectsByGoalID, completionsByProject, today, days)

	out := GoalProgressOutput{Goals: result}
	if input.IncludeDrift {
		s.attachDriftAnalysis(ctx, &out, input.Days)
	}

	return nil, out, nil
}

// buildGoalProgressList filters and assembles goal progress details.
func buildGoalProgressList(goals []goal.Goal, input GoalProgressInput, projectsByGoalID map[uuid.UUID][]string, completionsByProject map[string]int64, today time.Time, days int) []goalProgressDetail {
	result := make([]goalProgressDetail, 0)
	for gIdx := range goals {
		g := &goals[gIdx]
		if !goalMatchesFilter(g, input) {
			continue
		}
		gp := buildGoalDetail(g, projectsByGoalID, completionsByProject, today, days)
		result = append(result, gp)
	}
	return result
}

// goalMatchesFilter checks whether a goal passes the area/status filters.
func goalMatchesFilter(g *goal.Goal, input GoalProgressInput) bool {
	if input.Status == "" && (string(g.Status) == "done" || string(g.Status) == "abandoned") {
		return false
	}
	if input.Area != "" && g.Area != input.Area {
		return false
	}
	if input.Status != "" && string(g.Status) != input.Status {
		return false
	}
	return true
}

// buildGoalDetail assembles a single goal's progress detail.
func buildGoalDetail(g *goal.Goal, projectsByGoalID map[uuid.UUID][]string, completionsByProject map[string]int64, today time.Time, days int) goalProgressDetail {
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

	for _, pTitle := range gp.RelatedProjects {
		gp.RelatedTasksCompleted += completionsByProject[pTitle]
	}

	weeks := float64(days) / 7.0
	if weeks > 0 {
		gp.WeeklyTaskRate = float64(gp.RelatedTasksCompleted) / weeks
	}

	gp.OnTrackAssessment = assessOnTrack(gp.RelatedTasksCompleted, gp.WeeklyTaskRate, gp.DaysRemaining)
	return gp
}

// attachDriftAnalysis fetches drift data and attaches it to the output (best-effort).
func (s *Server) attachDriftAnalysis(ctx context.Context, out *GoalProgressOutput, inputDays int) {
	driftDays := clamp(inputDays, 7, 90, 30)
	drift, err := s.stats.Drift(ctx, driftDays)
	if err != nil {
		s.logger.Error("goal_progress: drift analysis", "error", err)
		return
	}
	areas := make([]driftAreaItem, len(drift.Areas))
	for i, a := range drift.Areas {
		areas[i] = driftAreaItem{
			Area:         a.Area,
			ActiveGoals:  a.ActiveGoals,
			EventCount:   a.EventCount,
			EventPercent: a.EventPercent,
			GoalPercent:  a.GoalPercent,
			DriftPercent: a.DriftPercent,
		}
	}
	out.Drift = &driftSummary{Period: drift.Period, Areas: areas}
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
