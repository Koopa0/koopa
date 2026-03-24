package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/koopa0/blog-backend/internal/flow"
	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/session"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// WeeklySummaryInput is the input for the get_weekly_summary tool.
type WeeklySummaryInput struct {
	WeeksBack int `json:"weeks_back,omitempty" jsonschema_description:"0 = current week, 1 = last week. Default 0, max 4."`
}

// WeeklySummaryOutput is the aggregated weekly report.
type WeeklySummaryOutput struct {
	Period           weeklyPeriod    `json:"period"`
	Tasks            weeklyTasks     `json:"tasks"`
	MetricsTrend     weeklyMetrics   `json:"metrics_trend"`
	ProjectHealth    []projectHealth `json:"project_health"`
	InsightsActivity weeklyInsights  `json:"insights_activity"`
	GoalAlignment    []weeklyGoal    `json:"goal_alignment"`
	Highlights       []string        `json:"highlights"`
	Concerns         []string        `json:"concerns"`
}

type weeklyPeriod struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type weeklyTasks struct {
	TotalCompleted int                `json:"total_completed"`
	ByProject      []projectTaskCount `json:"by_project"`
}

type projectTaskCount struct {
	Project   string `json:"project"`
	Completed int64  `json:"completed"`
}

type weeklyMetrics struct {
	DailyRates  []float64    `json:"daily_rates"`
	AvgCapacity float64      `json:"avg_capacity"`
	BestDay     *dayCapacity `json:"best_day,omitempty"`
	WorstDay    *dayCapacity `json:"worst_day,omitempty"`
}

type dayCapacity struct {
	Date     string `json:"date"`
	DayType  string `json:"day_type"`
	Capacity int    `json:"capacity"`
}

type weeklyInsights struct {
	NewInsights            int `json:"new_insights"`
	Verified               int `json:"verified"`
	Invalidated            int `json:"invalidated"`
	PendingRecommendations int `json:"pending_recommendations"`
}

type weeklyGoal struct {
	Title                 string   `json:"title"`
	Status                string   `json:"status"`
	Deadline              string   `json:"deadline,omitempty"`
	RelatedProjects       []string `json:"related_projects"`
	RelatedTasksCompleted int64    `json:"related_tasks_completed"`
	OnTrack               string   `json:"on_track"`
}

func (s *Server) getWeeklySummary(ctx context.Context, _ *mcp.CallToolRequest, input WeeklySummaryInput) (*mcp.CallToolResult, WeeklySummaryOutput, error) {
	weeksBack := clamp(input.WeeksBack, 0, 4, 0)

	now := time.Now().In(s.loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, s.loc)

	// Calculate week boundaries (Monday-based)
	weekday := int(today.Weekday())
	if weekday == 0 {
		weekday = 7 // Sunday = 7
	}
	thisMonday := today.AddDate(0, 0, -(weekday - 1))
	weekStart := thisMonday.AddDate(0, 0, -7*weeksBack)
	weekEnd := weekStart.AddDate(0, 0, 7)
	if weekEnd.After(today) {
		weekEnd = today.AddDate(0, 0, 1) // include today
	}

	out := WeeklySummaryOutput{
		Period: weeklyPeriod{
			From: weekStart.Format(time.DateOnly),
			To:   weekEnd.AddDate(0, 0, -1).Format(time.DateOnly),
		},
		Highlights: []string{},
		Concerns:   []string{},
	}

	// Fetch shared data once
	activeProjects, projErr := s.projects.ActiveProjects(ctx)
	if projErr != nil {
		s.logger.Error("weekly_summary: active projects", "error", projErr)
	}
	var metricsNotes []session.Note
	if s.sessionReader != nil {
		var metricsErr error
		metricsNotes, metricsErr = s.sessionReader.MetricsHistory(ctx, weekStart)
		if metricsErr != nil {
			s.logger.Error("weekly_summary: metrics history", "error", metricsErr)
		}
	}

	byProject := s.fetchWeeklyTasks(ctx, &out, weekStart)
	s.buildWeeklyMetrics(&out, metricsNotes)
	s.fetchWeeklyProjectHealth(ctx, &out, activeProjects, now)
	s.fetchWeeklyInsights(ctx, &out, weekStart)
	s.fetchWeeklyGoalAlignment(ctx, &out, activeProjects, byProject, weekStart, today)
	s.buildWeeklyTrendConcern(&out, metricsNotes)

	return nil, out, nil
}

// fetchWeeklyTasks fetches completed tasks grouped by project for the week.
// Returns the raw by-project data for reuse by goal alignment.
func (s *Server) fetchWeeklyTasks(ctx context.Context, out *WeeklySummaryOutput, weekStart time.Time) []flow.ProjectCompletion {
	byProject, err := s.tasks.CompletedByProjectSince(ctx, weekStart)
	if err != nil {
		s.logger.Error("weekly_summary: tasks by project", "error", err)
	}
	var totalCompleted int64
	out.Tasks.ByProject = make([]projectTaskCount, 0, len(byProject))
	for _, p := range byProject {
		out.Tasks.ByProject = append(out.Tasks.ByProject, projectTaskCount{
			Project:   p.ProjectTitle,
			Completed: p.Completed,
		})
		totalCompleted += p.Completed
	}
	out.Tasks.TotalCompleted = int(totalCompleted)
	return byProject
}

// buildWeeklyMetrics computes trend, best/worst days, and highlights from pre-fetched metrics.
func (s *Server) buildWeeklyMetrics(out *WeeklySummaryOutput, metricsNotes []session.Note) {
	entries := buildDailyMetricsList(metricsNotes)

	out.MetricsTrend.DailyRates = make([]float64, 0, len(entries))
	var totalCapacity float64
	var bestDay, worstDay *dayCapacity
	for _, e := range entries {
		out.MetricsTrend.DailyRates = append(out.MetricsTrend.DailyRates, e.CompletionRate)
		totalCapacity += float64(e.TasksCompleted)

		d, parseErr := time.Parse(time.DateOnly, e.Date)
		if parseErr != nil {
			continue
		}
		dc := &dayCapacity{
			Date:     e.Date,
			DayType:  d.Weekday().String(),
			Capacity: e.TasksCompleted,
		}
		if bestDay == nil || e.TasksCompleted > bestDay.Capacity {
			bestDay = dc
		}
		if worstDay == nil || e.TasksCompleted < worstDay.Capacity {
			worstDay = dc
		}
	}
	if len(entries) > 0 {
		out.MetricsTrend.AvgCapacity = totalCapacity / float64(len(entries))
	}
	out.MetricsTrend.BestDay = bestDay
	out.MetricsTrend.WorstDay = worstDay

	for _, e := range entries {
		if e.CompletionRate > 0.9 {
			out.Highlights = append(out.Highlights, fmt.Sprintf("%s: %.0f%% completion rate", e.Date, e.CompletionRate*100))
		}
	}
}

// fetchWeeklyProjectHealth computes health from pre-fetched projects and appends neglect concerns.
func (s *Server) fetchWeeklyProjectHealth(ctx context.Context, out *WeeklySummaryOutput, projects []project.Project, now time.Time) {
	allPending, err := s.tasks.PendingTasksWithProject(ctx, nil, 100)
	if err != nil {
		s.logger.Error("weekly_summary: pending tasks", "error", err)
	}

	tasksByProject := make(map[string]int)
	for i := range allPending {
		if allPending[i].ProjectSlug != "" {
			tasksByProject[allPending[i].ProjectSlug]++
		}
	}

	out.ProjectHealth = make([]projectHealth, 0, len(projects))
	for pIdx := range projects {
		p := &projects[pIdx]
		ph := projectHealth{
			Slug:            p.Slug,
			Title:           p.Title,
			Status:          string(p.Status),
			PendingTasks:    tasksByProject[p.Slug],
			ExpectedCadence: p.ExpectedCadence,
		}
		if p.LastActivityAt != nil {
			ph.DaysSinceActivity = int(now.Sub(*p.LastActivityAt).Hours() / 24)
		}
		ph.IsNeglected = isProjectNeglected(ph.DaysSinceActivity, p.ExpectedCadence)
		out.ProjectHealth = append(out.ProjectHealth, ph)

		if ph.IsNeglected {
			out.Concerns = append(out.Concerns, fmt.Sprintf("Project %q neglected: %d days since activity (cadence: %s)", p.Title, ph.DaysSinceActivity, p.ExpectedCadence))
		}
	}
}

// fetchWeeklyInsights fetches insight activity (new, verified, invalidated) and pending recommendations.
func (s *Server) fetchWeeklyInsights(ctx context.Context, out *WeeklySummaryOutput, weekStart time.Time) {
	if s.sessionReader == nil {
		return
	}

	allInsights, insightErr := s.sessionReader.InsightsSince(ctx, weekStart)
	if insightErr != nil {
		s.logger.Error("weekly_summary: insights", "error", insightErr)
	}
	for i := range allInsights {
		delta := parseInsightDelta(&allInsights[i])
		switch delta.CurrentStatus {
		case "unverified":
			out.InsightsActivity.NewInsights++
		case "verified":
			out.InsightsActivity.Verified++
			out.Highlights = append(out.Highlights, fmt.Sprintf("Insight verified: %s", delta.Hypothesis))
		case "invalidated":
			out.InsightsActivity.Invalidated++
		}
	}

	recNotes, recErr := s.sessionReader.InsightsByCategory(ctx, "unverified", "action_recommendation", 10)
	if recErr == nil {
		out.InsightsActivity.PendingRecommendations = len(recNotes)
	}
}

// fetchWeeklyGoalAlignment computes on-track assessment using
// goal_id FK project matching and task completions. Appends off-track concerns.
func (s *Server) fetchWeeklyGoalAlignment(ctx context.Context, out *WeeklySummaryOutput, projects []project.Project, byProject []flow.ProjectCompletion, weekStart, today time.Time) {
	goals, err := s.goals.Goals(ctx)
	if err != nil {
		s.logger.Error("weekly_summary: goals", "error", err)
	}

	projectsByGoalID := buildProjectsByGoalID(projects)
	completionsByProject := buildCompletionsByProject(byProject)

	out.GoalAlignment = make([]weeklyGoal, 0)
	for i := range goals {
		g := &goals[i]
		if string(g.Status) == "done" || string(g.Status) == "abandoned" {
			continue
		}
		wg := buildWeeklyGoal(g, projectsByGoalID, completionsByProject, today)
		if wg.OnTrack != "on_track" {
			out.Concerns = append(out.Concerns, fmt.Sprintf("Goal %q: %s (completed %d related tasks this week)", g.Title, wg.OnTrack, wg.RelatedTasksCompleted))
		}
		out.GoalAlignment = append(out.GoalAlignment, wg)
	}

	buildLogs, blErr := s.contents.RecentByType(ctx, "build-log", weekStart, 10)
	if blErr == nil {
		for i := range buildLogs {
			out.Highlights = append(out.Highlights, fmt.Sprintf("Build log: %s", buildLogs[i].Title))
		}
	}
}

// buildProjectsByGoalID groups project titles by their goal FK.
func buildProjectsByGoalID(projects []project.Project) map[uuid.UUID][]string {
	m := make(map[uuid.UUID][]string)
	for i := range projects {
		if projects[i].GoalID != nil {
			m[*projects[i].GoalID] = append(m[*projects[i].GoalID], projects[i].Title)
		}
	}
	return m
}

// buildCompletionsByProject maps project titles to their completion counts.
func buildCompletionsByProject(byProject []flow.ProjectCompletion) map[string]int64 {
	m := make(map[string]int64)
	for _, p := range byProject {
		m[p.ProjectTitle] = p.Completed
	}
	return m
}

// buildWeeklyGoal assembles a weeklyGoal with task completions and on-track assessment.
func buildWeeklyGoal(g *goal.Goal, projectsByGoalID map[uuid.UUID][]string, completionsByProject map[string]int64, today time.Time) weeklyGoal {
	wg := weeklyGoal{
		Title:           g.Title,
		Status:          string(g.Status),
		RelatedProjects: projectsByGoalID[g.ID],
	}
	if g.Deadline != nil {
		wg.Deadline = g.Deadline.Format(time.DateOnly)
	}
	if wg.RelatedProjects == nil {
		wg.RelatedProjects = []string{}
	}

	for _, pTitle := range wg.RelatedProjects {
		wg.RelatedTasksCompleted += completionsByProject[pTitle]
	}

	var daysRemaining int
	if g.Deadline != nil {
		daysRemaining = int(g.Deadline.Sub(today).Hours() / 24)
	}
	weeklyRate := float64(wg.RelatedTasksCompleted)
	wg.OnTrack = assessOnTrack(wg.RelatedTasksCompleted, weeklyRate, daysRemaining)
	return wg
}

// fetchWeeklyTrendConcern checks if the completion rate trend is declining and appends a concern.
// buildWeeklyTrendConcern appends a concern if the completion rate trend is declining.
func (s *Server) buildWeeklyTrendConcern(out *WeeklySummaryOutput, metricsNotes []session.Note) {
	entries := buildDailyMetricsList(metricsNotes)
	if trend := computeTrend(entries); trend == "down" {
		out.Concerns = append(out.Concerns, "Completion rate trend is declining")
	}
}
