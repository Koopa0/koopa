package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/koopa0/blog-backend/internal/task"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ReflectionContextInput is the input for the get_reflection_context tool.
type ReflectionContextInput struct {
	Date string `json:"date,omitempty" jsonschema_description:"ISO date YYYY-MM-DD (default today)"`
}

// ReflectionContextOutput aggregates everything needed for evening reflection.
type ReflectionContextOutput struct {
	Date                 string                 `json:"date"`
	TodayPlan            *reflectionPlanNote    `json:"today_plan,omitempty"`
	TodayCompletions     []todayCompletion      `json:"today_completions"`
	MyDayStatus          []myDayTaskStatus      `json:"my_day_status"`
	TasksPlannedToday    int                    `json:"tasks_planned_today"`
	TasksCompletedToday  int                    `json:"tasks_completed_today"`
	DailySummary         *dailySummaryHint      `json:"daily_summary,omitempty"`
	UnverifiedInsights   []insightBrief         `json:"unverified_insights"`
	PlanningHistory      planningHistorySummary `json:"planning_history"`
	YesterdayAdjustments []string               `json:"yesterday_adjustments,omitempty"`
}

// reflectionPlanNote is the morning plan note with parsed metadata.
type reflectionPlanNote struct {
	Content          string   `json:"content"`
	CommittedTaskIDs []string `json:"committed_task_ids,omitempty"`
	BufferTaskIDs    []string `json:"buffer_task_ids,omitempty"`
	Source           string   `json:"source"`
	CreatedAt        string   `json:"created_at"`
}

// myDayTaskStatus shows whether each My Day task was completed.
type myDayTaskStatus struct {
	TaskID      string `json:"task_id"`
	Title       string `json:"title"`
	Project     string `json:"project,omitempty"`
	IsCompleted bool   `json:"is_completed"`
}

func (s *Server) getReflectionContext(ctx context.Context, _ *mcp.CallToolRequest, input ReflectionContextInput) (*mcp.CallToolResult, ReflectionContextOutput, error) {
	now := time.Now().In(s.loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, s.loc)
	tomorrow := today.AddDate(0, 0, 1)

	if input.Date != "" {
		parsed, err := time.Parse(time.DateOnly, input.Date)
		if err != nil {
			return nil, ReflectionContextOutput{}, err
		}
		today = parsed
		tomorrow = today.AddDate(0, 0, 1)
	}

	out := ReflectionContextOutput{
		Date: today.Format("2006-01-02 (Monday)"),
	}

	// 1. Today's plan note
	s.fetchReflectionPlan(ctx, &out, today, tomorrow)

	// 2. Today's completions (from activity_events — source of truth)
	s.fetchReflectionCompletions(ctx, &out, today, tomorrow)
	out.TasksCompletedToday = len(out.TodayCompletions)

	// Fetch daily summary hint once — used by both My Day status and daily summary
	hint, hintErr := s.tasks.DailySummaryHintForDate(ctx, today, tomorrow)
	if hintErr != nil {
		s.logger.Error("reflection_context: daily summary hint", "error", hintErr)
	}

	// 3. My Day task status (join pending tasks with completions)
	s.fetchReflectionMyDayStatus(ctx, &out, hint)

	// 4. Daily summary from tasks table
	setReflectionDailySummary(&out, hint)

	// 5. Unverified insights
	s.fetchReflectionInsights(ctx, &out)

	// 6. Planning history (last 7 days)
	s.fetchReflectionPlanningHistory(ctx, &out, now)

	// Defaults
	if out.TodayCompletions == nil {
		out.TodayCompletions = []todayCompletion{}
	}
	if out.MyDayStatus == nil {
		out.MyDayStatus = []myDayTaskStatus{}
	}
	if out.UnverifiedInsights == nil {
		out.UnverifiedInsights = []insightBrief{}
	}
	if out.PlanningHistory.Entries == nil {
		out.PlanningHistory.Entries = []dailyMetrics{}
	}

	return nil, out, nil
}

// fetchReflectionPlan fetches today's plan note and parses committed/buffer task IDs.
func (s *Server) fetchReflectionPlan(ctx context.Context, out *ReflectionContextOutput, today, tomorrow time.Time) {
	if s.sessions == nil {
		return
	}

	planType := "plan"
	notes, err := s.sessions.NotesByDate(ctx, today, tomorrow, &planType)
	if err != nil || len(notes) == 0 {
		return
	}

	// Use the most recent plan note for today
	n := &notes[0]
	plan := &reflectionPlanNote{
		Content:   n.Content,
		Source:    n.Source,
		CreatedAt: n.CreatedAt.Format(time.RFC3339),
	}

	// Parse committed/buffer task IDs from metadata
	if len(n.Metadata) > 0 {
		var meta struct {
			CommittedTaskIDs []string `json:"committed_task_ids"`
			BufferTaskIDs    []string `json:"buffer_task_ids"`
		}
		if json.Unmarshal(n.Metadata, &meta) == nil {
			plan.CommittedTaskIDs = meta.CommittedTaskIDs
			plan.BufferTaskIDs = meta.BufferTaskIDs
			out.TasksPlannedToday = len(meta.CommittedTaskIDs)
		}
	}

	out.TodayPlan = plan
}

// fetchReflectionMyDayStatus builds the My Day task completion status.
// Joins pending My Day tasks with today's completions to show which were done.
func (s *Server) fetchReflectionMyDayStatus(ctx context.Context, out *ReflectionContextOutput, hint *task.DailySummaryHint) {
	allTasks, err := s.tasks.PendingTasksWithProject(ctx, nil, nil, 100)
	if err != nil {
		s.logger.Error("reflection_context: pending tasks", "error", err)
		return
	}

	// Build set of completed task titles for matching
	completedTitles := make(map[string]bool)
	for _, tc := range out.TodayCompletions {
		completedTitles[tc.Title] = true
	}
	if hint != nil {
		for _, t := range hint.CompletedTitles {
			completedTitles[t] = true
		}
	}

	out.MyDayStatus = make([]myDayTaskStatus, 0)
	for i := range allTasks {
		t := &allTasks[i]
		if !t.MyDay {
			continue
		}
		out.MyDayStatus = append(out.MyDayStatus, myDayTaskStatus{
			TaskID:      t.ID.String(),
			Title:       t.Title,
			Project:     t.ProjectTitle,
			IsCompleted: completedTitles[t.Title],
		})
	}
}

// fetchReflectionCompletions queries activity_events for today's task completions.
func (s *Server) fetchReflectionCompletions(ctx context.Context, out *ReflectionContextOutput, today, tomorrow time.Time) {
	events, err := s.activity.EventsByFilters(ctx, today, tomorrow, nil, nil, 200)
	if err != nil {
		s.logger.Error("reflection_context: today completions", "error", err)
		out.TodayCompletions = []todayCompletion{}
		return
	}

	seen := make(map[string]bool)
	out.TodayCompletions = make([]todayCompletion, 0)
	for i := range events {
		e := &events[i]
		if !isCompletionEvent(e.EventType, e.Source, e.Metadata) {
			continue
		}
		title := ""
		if e.Title != nil {
			title = strings.TrimPrefix(*e.Title, "Completed: ")
		}
		if seen[title] {
			continue
		}
		seen[title] = true
		tc := todayCompletion{
			CompletedVia: e.Source,
			Title:        title,
		}
		if e.Project != nil {
			tc.Project = *e.Project
		}
		out.TodayCompletions = append(out.TodayCompletions, tc)
	}
}

// setReflectionDailySummary populates the daily summary from a pre-fetched hint.
func setReflectionDailySummary(out *ReflectionContextOutput, hint *task.DailySummaryHint) {
	if hint == nil {
		return
	}
	out.DailySummary = &dailySummaryHint{
		MyDayTasksTotal:     hint.MyDayTasksTotal,
		MyDayTasksCompleted: hint.MyDayTasksCompleted,
		NonMyDayCompleted:   hint.NonMyDayCompleted,
		TotalCompleted:      hint.TotalCompleted,
		CompletedTitles:     hint.CompletedTitles,
	}
	if out.DailySummary.CompletedTitles == nil {
		out.DailySummary.CompletedTitles = []string{}
	}
}

// fetchReflectionInsights fetches unverified insights for review.
func (s *Server) fetchReflectionInsights(ctx context.Context, out *ReflectionContextOutput) {
	if s.sessions == nil {
		return
	}

	unverified := "unverified"
	insightNotes, err := s.sessions.InsightsByStatus(ctx, &unverified, nil, 10)
	if err != nil {
		s.logger.Error("reflection_context: insights", "error", err)
		return
	}
	out.UnverifiedInsights = make([]insightBrief, 0, len(insightNotes))
	for i := range insightNotes {
		out.UnverifiedInsights = append(out.UnverifiedInsights, parseInsightBrief(&insightNotes[i]))
	}
}

// fetchReflectionPlanningHistory fetches metrics history and yesterday's adjustments.
func (s *Server) fetchReflectionPlanningHistory(ctx context.Context, out *ReflectionContextOutput, now time.Time) {
	if s.sessions == nil {
		return
	}

	since := now.AddDate(0, 0, -30)
	metricsNotes, err := s.sessions.MetricsHistory(ctx, since)
	if err != nil {
		s.logger.Error("reflection_context: metrics history", "error", err)
		return
	}
	out.PlanningHistory = buildPlanningHistory(metricsNotes, 7)

	if len(metricsNotes) > 0 {
		out.YesterdayAdjustments = parseAdjustments(metricsNotes[0].Metadata)
	}
}
