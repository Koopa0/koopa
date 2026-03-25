package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/session"
	"github.com/koopa0/blog-backend/internal/task"
)

// MorningContextInput is the input for the get_morning_context tool.
type MorningContextInput struct {
	ActivityDays int `json:"activity_days,omitempty" jsonschema_description:"days of activity to include (default 3)"`
	BuildLogDays int `json:"build_log_days,omitempty" jsonschema_description:"days of build logs to include (default 7)"`
}

// MorningContextOutput is the aggregated output for daily planning.
type MorningContextOutput struct {
	Date                   string                 `json:"date"`
	SessionGap             int                    `json:"session_gap"`
	LastSessionDate        string                 `json:"last_session_date,omitempty"`
	OverdueTasks           []morningTask          `json:"overdue_tasks"`
	TodayTasks             []morningTask          `json:"today_tasks"`
	UpcomingTasks          []morningTask          `json:"upcoming_tasks"`
	MyDayTasks             []morningTask          `json:"my_day_tasks"`
	RecentActivity         activitySummary        `json:"recent_activity"`
	RecentBuildLogs        []buildLogBrief        `json:"recent_build_logs"`
	Projects               []projectHealth        `json:"projects"`
	Goals                  []goalBrief            `json:"goals"`
	LatestPlan             string                 `json:"latest_plan,omitempty"`
	LatestPlanDate         string                 `json:"latest_plan_date,omitempty"`
	LatestReflection       string                 `json:"latest_reflection,omitempty"`
	LatestReflectionDate   string                 `json:"latest_reflection_date,omitempty"`
	YesterdayAdjustments   []string               `json:"yesterday_adjustments,omitempty"`
	PlanningHistory        planningHistorySummary `json:"planning_history"`
	ActiveInsights         []insightBrief         `json:"active_insights"`
	PendingRecommendations []insightBrief         `json:"pending_recommendations"`
	TotalUnverified        int64                  `json:"total_unverified"`
	DailySummary           *dailySummaryHint      `json:"daily_summary,omitempty"`
	TodayCompletions       []todayCompletion      `json:"today_completions"`
	RSSHighlightCount      int                    `json:"rss_highlight_count"`
	TopRSSHighlight        string                 `json:"top_rss_highlight,omitempty"`
	UrgentRSS              []urgentRSSItem        `json:"urgent_rss"`
}

// urgentRSSItem represents a high-priority RSS article for morning planning.
type urgentRSSItem struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	SourceName  string   `json:"source_name"`
	URL         string   `json:"url"`
	Topics      []string `json:"topics"`
	CollectedAt string   `json:"collected_at"`
}

// dailySummaryHint provides computed task metrics for evening reflection.
type dailySummaryHint struct {
	MyDayTasksTotal     int      `json:"my_day_tasks_total"`
	MyDayTasksCompleted int      `json:"my_day_tasks_completed"`
	NonMyDayCompleted   int      `json:"non_my_day_completed"`
	TotalCompleted      int      `json:"total_completed"`
	CompletedTitles     []string `json:"completed_titles"`
}

// todayCompletion represents a task completed today, sourced from activity_events.
// This is the single source of truth for today's completions — more reliable than
// tasks.completed_at which only records the first completion for recurring tasks.
type todayCompletion struct {
	Title        string `json:"title"`
	Project      string `json:"project,omitempty"`
	CompletedVia string `json:"completed_via"` // "mcp" or "notion"
}

type dailyMetrics struct {
	Date                    string  `json:"date"`
	TasksPlanned            int     `json:"tasks_planned"`
	TasksCompleted          int     `json:"tasks_completed"`
	TasksCommitted          int     `json:"tasks_committed,omitempty"`
	TasksPulled             int     `json:"tasks_pulled,omitempty"`
	CompletionRate          float64 `json:"completion_rate"`
	CommittedCompletionRate float64 `json:"committed_completion_rate,omitempty"`
	EnergyPattern           string  `json:"energy_pattern,omitempty"`
}

type planningHistorySummary struct {
	Days              int                `json:"days"`
	Entries           []dailyMetrics     `json:"entries"`
	AvgCompletionRate float64            `json:"avg_completion_rate"`
	AvgCommittedRate  float64            `json:"avg_committed_rate"`
	AvgDailyCapacity  float64            `json:"avg_daily_capacity"`
	Trend             string             `json:"trend"`
	CapacityVariance  float64            `json:"capacity_variance"`
	CapacityByDayType map[string]float64 `json:"capacity_by_day_type"`
	MonthlySummary    *monthlySummary    `json:"monthly_summary,omitempty"`
}

type monthlySummary struct {
	TotalDaysTracked  int     `json:"total_days_tracked"`
	AvgCompletionRate float64 `json:"avg_completion_rate"`
	AvgDailyCapacity  float64 `json:"avg_daily_capacity"`
	BestDayType       string  `json:"best_day_type"`
	WorstDayType      string  `json:"worst_day_type"`
}

type insightBrief struct {
	ID         int64  `json:"id"`
	Hypothesis string `json:"hypothesis"`
	Status     string `json:"status"`
	Project    string `json:"project,omitempty"`
	CreatedAt  string `json:"created_at"`
}

type morningTask struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Due         string `json:"due,omitempty"`
	OverdueDays int    `json:"overdue_days,omitempty"`
	SkipCount   int    `json:"skip_count,omitempty"`
	Priority    string `json:"priority,omitempty"`
	Energy      string `json:"energy,omitempty"`
	Project     string `json:"project,omitempty"`
	IsRecurring bool   `json:"is_recurring"`
}

type activitySummary struct {
	Period        string         `json:"period"`
	BySource      map[string]int `json:"by_source"`
	ByProject     map[string]int `json:"by_project"`
	TopEvents     []string       `json:"top_events"`
	GithubCommits int            `json:"github_commits"`
}

type buildLogBrief struct {
	Slug        string `json:"slug"`
	Title       string `json:"title"`
	Project     string `json:"project,omitempty"`
	SessionType string `json:"session_type,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type projectHealth struct {
	Slug              string `json:"slug"`
	Title             string `json:"title"`
	Status            string `json:"status"`
	DaysSinceActivity int    `json:"days_since_activity"`
	PendingTasks      int    `json:"pending_tasks"`
	ExpectedCadence   string `json:"expected_cadence"`
	IsNeglected       bool   `json:"is_neglected"`
}

type goalBrief struct {
	Title    string `json:"title"`
	Status   string `json:"status"`
	Area     string `json:"area,omitempty"`
	Deadline string `json:"deadline,omitempty"`
}

func (s *Server) getMorningContext(ctx context.Context, _ *mcp.CallToolRequest, input MorningContextInput) (*mcp.CallToolResult, MorningContextOutput, error) {
	activityDays := clamp(input.ActivityDays, 1, 14, 3)
	buildLogDays := clamp(input.BuildLogDays, 1, 30, 7)

	now := time.Now().In(s.loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, s.loc)
	tomorrow := today.AddDate(0, 0, 1)

	out := MorningContextOutput{
		Date: now.Format("2006-01-02 (Monday)"),
	}

	allTasks := s.fetchMorningTasks(ctx, &out, today, tomorrow)
	s.fetchMorningActivity(ctx, &out, now, activityDays)
	s.fetchMorningBuildLogs(ctx, &out, now, buildLogDays)
	s.fetchMorningProjectHealth(ctx, &out, allTasks, now)
	s.fetchMorningGoals(ctx, &out)
	s.fetchMorningSessionData(ctx, &out, today, now)
	s.fetchMorningRSSHighlights(ctx, &out, now)
	s.fetchMorningDailySummary(ctx, &out, today, tomorrow)
	s.fetchTodayCompletions(ctx, &out, today, tomorrow)

	return nil, out, nil
}

// fetchMorningTasks fetches pending tasks and categorizes them into overdue, today,
// upcoming, and my-day buckets. Returns the raw task list for reuse by project health.
func (s *Server) fetchMorningTasks(ctx context.Context, out *MorningContextOutput, today, tomorrow time.Time) []task.PendingTaskDetail {
	weekEnd := today.AddDate(0, 0, 7)

	allTasks, err := s.tasks.PendingTasksWithProject(ctx, nil, 100)
	if err != nil {
		s.logger.Error("morning_context: pending tasks", "error", err)
		out.OverdueTasks = []morningTask{}
		out.TodayTasks = []morningTask{}
		out.UpcomingTasks = []morningTask{}
		out.MyDayTasks = []morningTask{}
		return nil
	}

	for tIdx := range allTasks {
		t := allTasks[tIdx]
		mt := morningTask{
			ID:          t.ID.String(),
			Title:       t.Title,
			Priority:    t.Priority,
			Energy:      t.Energy,
			Project:     t.ProjectTitle,
			IsRecurring: t.RecurInterval != nil && *t.RecurInterval > 0,
		}
		if t.Due != nil {
			mt.Due = t.Due.Format(time.DateOnly)
			dueDate := time.Date(t.Due.Year(), t.Due.Month(), t.Due.Day(), 0, 0, 0, 0, t.Due.Location())
			switch {
			case dueDate.Before(today):
				mt.OverdueDays = int(today.Sub(dueDate).Hours() / 24)
				mt.SkipCount = computeSkipCount(mt.OverdueDays, mt.IsRecurring, t.RecurInterval)
				out.OverdueTasks = append(out.OverdueTasks, mt)
			case dueDate.Before(tomorrow):
				out.TodayTasks = append(out.TodayTasks, mt)
			case dueDate.Before(weekEnd):
				out.UpcomingTasks = append(out.UpcomingTasks, mt)
			}
		}
		if t.MyDay {
			out.MyDayTasks = append(out.MyDayTasks, mt)
		}
	}

	if out.OverdueTasks == nil {
		out.OverdueTasks = []morningTask{}
	}
	if out.TodayTasks == nil {
		out.TodayTasks = []morningTask{}
	}
	if out.UpcomingTasks == nil {
		out.UpcomingTasks = []morningTask{}
	}
	if out.MyDayTasks == nil {
		out.MyDayTasks = []morningTask{}
	}

	return allTasks
}

// fetchMorningActivity fetches recent activity events and summarizes them by source and project.
func (s *Server) fetchMorningActivity(ctx context.Context, out *MorningContextOutput, now time.Time, activityDays int) {
	actStart := now.AddDate(0, 0, -activityDays)
	events, err := s.activity.EventsByFilters(ctx, actStart, now, nil, nil, 200)
	if err != nil {
		s.logger.Error("morning_context: activity", "error", err)
		return
	}

	summary := activitySummary{
		Period:    fmt.Sprintf("last %d days", activityDays),
		BySource:  make(map[string]int),
		ByProject: make(map[string]int),
	}
	for i := range events {
		e := &events[i]
		summary.BySource[e.Source]++
		if e.Project != nil && *e.Project != "" {
			summary.ByProject[*e.Project]++
		}
		if e.Source == "github" && e.EventType == "push" {
			summary.GithubCommits++
		}
		if len(summary.TopEvents) < 5 && e.Title != nil {
			summary.TopEvents = append(summary.TopEvents, *e.Title)
		}
	}
	if summary.TopEvents == nil {
		summary.TopEvents = []string{}
	}
	out.RecentActivity = summary
}

// fetchMorningBuildLogs fetches recent build log content entries.
func (s *Server) fetchMorningBuildLogs(ctx context.Context, out *MorningContextOutput, now time.Time, buildLogDays int) {
	buildLogStart := now.AddDate(0, 0, -buildLogDays)
	buildLogs, err := s.contents.RecentByType(ctx, "build-log", buildLogStart, 3)
	if err != nil {
		s.logger.Error("morning_context: build logs", "error", err)
	}
	out.RecentBuildLogs = make([]buildLogBrief, 0, len(buildLogs))
	for i := range buildLogs {
		c := &buildLogs[i]
		out.RecentBuildLogs = append(out.RecentBuildLogs, buildLogBrief{
			Slug:        c.Slug,
			Title:       c.Title,
			Project:     extractFrontmatter(c.Body, "project"),
			SessionType: extractFrontmatter(c.Body, "session_type"),
			CreatedAt:   c.CreatedAt.Format(time.DateOnly),
		})
	}
}

// fetchMorningProjectHealth fetches active projects and computes health metrics
// using the pending task list for per-project task counts.
func (s *Server) fetchMorningProjectHealth(ctx context.Context, out *MorningContextOutput, allTasks []task.PendingTaskDetail, now time.Time) {
	projects, err := s.projects.ActiveProjects(ctx)
	if err != nil {
		s.logger.Error("morning_context: projects", "error", err)
		return
	}

	tasksByProject := make(map[string]int)
	for i := range allTasks {
		if allTasks[i].ProjectSlug != "" {
			tasksByProject[allTasks[i].ProjectSlug]++
		}
	}

	out.Projects = make([]projectHealth, 0, len(projects))
	for i := range projects {
		p := &projects[i]
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
		out.Projects = append(out.Projects, ph)
	}
}

// fetchMorningGoals fetches active goals (excluding done/abandoned).
func (s *Server) fetchMorningGoals(ctx context.Context, out *MorningContextOutput) {
	goals, err := s.goals.Goals(ctx)
	if err != nil {
		s.logger.Error("morning_context: goals", "error", err)
		return
	}

	out.Goals = make([]goalBrief, 0)
	for i := range goals {
		g := &goals[i]
		if string(g.Status) == "done" || string(g.Status) == "abandoned" {
			continue
		}
		gb := goalBrief{
			Title:  g.Title,
			Status: string(g.Status),
			Area:   g.Area,
		}
		if g.Deadline != nil {
			gb.Deadline = g.Deadline.Format(time.DateOnly)
		}
		out.Goals = append(out.Goals, gb)
	}
}

// fetchMorningSessionData fetches session gap, reflection, planning history,
// insights, recommendations, and yesterday adjustments.
func (s *Server) fetchMorningSessionData(ctx context.Context, out *MorningContextOutput, today, now time.Time) {
	if s.sessionReader == nil {
		s.ensureSessionDefaults(out)
		return
	}

	lastSession, gapErr := s.sessionReader.LatestNoteBySource(ctx, "claude")
	if gapErr == nil {
		sessionDate := time.Date(lastSession.NoteDate.Year(), lastSession.NoteDate.Month(), lastSession.NoteDate.Day(), 0, 0, 0, 0, lastSession.NoteDate.Location())
		out.SessionGap = int(today.Sub(sessionDate).Hours() / 24)
		out.LastSessionDate = lastSession.NoteDate.Format(time.DateOnly)
	}

	plan, planErr := s.sessionReader.LatestNoteByType(ctx, "plan")
	if planErr == nil {
		out.LatestPlan = plan.Content
		out.LatestPlanDate = plan.NoteDate.Format(time.DateOnly)
	}

	refl, reflErr := s.sessionReader.LatestNoteByType(ctx, "reflection")
	if reflErr == nil {
		out.LatestReflection = refl.Content
		out.LatestReflectionDate = refl.NoteDate.Format(time.DateOnly)
	}

	since := now.AddDate(0, 0, -30)
	metricsNotes, metricsErr := s.sessionReader.MetricsHistory(ctx, since)
	if metricsErr != nil {
		s.logger.Error("morning_context: planning history", "error", metricsErr)
	}
	out.PlanningHistory = buildPlanningHistory(metricsNotes, 7)

	s.archiveStaleInsights(ctx, now)
	s.fetchMorningInsights(ctx, out)

	if len(metricsNotes) > 0 {
		out.YesterdayAdjustments = parseAdjustments(metricsNotes[0].Metadata)
	}

	s.ensureSessionDefaults(out)
}

// ensureSessionDefaults fills nil slices in session-related output fields.
func (*Server) ensureSessionDefaults(out *MorningContextOutput) {
	if out.PlanningHistory.Entries == nil {
		out.PlanningHistory.Entries = []dailyMetrics{}
	}
	if out.ActiveInsights == nil {
		out.ActiveInsights = []insightBrief{}
	}
	if out.PendingRecommendations == nil {
		out.PendingRecommendations = []insightBrief{}
	}
}

// archiveStaleInsights lazily auto-archives insights older than 14 days.
func (s *Server) archiveStaleInsights(ctx context.Context, now time.Time) {
	if s.sessionWriter == nil {
		return
	}
	cutoff := now.AddDate(0, 0, -14)
	n, err := s.sessionWriter.ArchiveStaleInsights(ctx, cutoff)
	if err != nil {
		s.logger.Error("morning_context: auto-archive insights", "error", err)
	} else if n > 0 {
		s.logger.Info("auto-archived stale insights", "count", n)
	}
}

// fetchMorningInsights fetches active unverified insights, their total count,
// and pending action recommendations.
func (s *Server) fetchMorningInsights(ctx context.Context, out *MorningContextOutput) {
	unverified := "unverified"
	insightNotes, insightErr := s.sessionReader.InsightsByStatus(ctx, &unverified, nil, 5)
	if insightErr != nil {
		s.logger.Error("morning_context: active insights", "error", insightErr)
	}
	out.ActiveInsights = make([]insightBrief, 0, len(insightNotes))
	for i := range insightNotes {
		out.ActiveInsights = append(out.ActiveInsights, parseInsightBrief(&insightNotes[i]))
	}

	unverifiedCount, countErr := s.sessionReader.CountInsightsByStatus(ctx, &unverified)
	if countErr != nil {
		s.logger.Error("morning_context: counting unverified insights", "error", countErr)
	}
	out.TotalUnverified = unverifiedCount

	recNotes, recErr := s.sessionReader.InsightsByCategory(ctx, "unverified", "action_recommendation", 3)
	if recErr != nil {
		s.logger.Error("morning_context: pending recommendations", "error", recErr)
	}
	if len(recNotes) > 0 {
		out.PendingRecommendations = make([]insightBrief, 0, len(recNotes))
		for i := range recNotes {
			out.PendingRecommendations = append(out.PendingRecommendations, parseInsightBrief(&recNotes[i]))
		}
	}
}

// fetchMorningRSSHighlights fetches top RSS highlights and urgent high-priority items.
func (s *Server) fetchMorningRSSHighlights(ctx context.Context, out *MorningContextOutput, now time.Time) {
	out.UrgentRSS = []urgentRSSItem{}

	if s.collectedHighlights == nil {
		return
	}
	weekAgo := now.AddDate(0, 0, -7)
	highlights, hlErr := s.collectedHighlights.TopRelevantCollected(ctx, weekAgo, 20)
	if hlErr != nil {
		s.logger.Error("morning_context: rss highlights", "error", hlErr)
		return
	}
	if len(highlights) > 0 {
		out.RSSHighlightCount = len(highlights)
		out.TopRSSHighlight = highlights[0].Title
	}

	// Fetch urgent RSS from high-priority feeds (past 24 hours)
	if s.collectedUrgent == nil {
		return
	}
	dayAgo := now.AddDate(0, 0, -1)
	urgent, urgentErr := s.collectedUrgent.HighPriorityRecent(ctx, dayAgo, 10)
	if urgentErr != nil {
		s.logger.Error("morning_context: urgent rss", "error", urgentErr)
		return
	}
	for i := range urgent {
		out.UrgentRSS = append(out.UrgentRSS, urgentRSSItem{
			ID:          urgent[i].ID.String(),
			Title:       urgent[i].Title,
			SourceName:  urgent[i].SourceName,
			URL:         urgent[i].SourceURL,
			Topics:      urgent[i].Topics,
			CollectedAt: urgent[i].CollectedAt.Format(time.RFC3339),
		})
	}
}

// fetchMorningDailySummary fetches the daily summary hint for evening reflection.
func (s *Server) fetchMorningDailySummary(ctx context.Context, out *MorningContextOutput, today, tomorrow time.Time) {
	hint, hintErr := s.tasks.DailySummaryHintForDate(ctx, today, tomorrow)
	if hintErr != nil {
		s.logger.Error("morning_context: daily summary hint", "error", hintErr)
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

// fetchTodayCompletions queries activity_events for today's task completions.
// Uses activity_events as source of truth (not tasks.completed_at) because:
// - recurring tasks only record first completion in tasks.completed_at
// - activity_events capture every completion with audit trail
func (s *Server) fetchTodayCompletions(ctx context.Context, out *MorningContextOutput, today, tomorrow time.Time) {
	events, err := s.activity.EventsByFilters(ctx, today, tomorrow, nil, nil, 200)
	if err != nil {
		s.logger.Error("morning_context: today completions", "error", err)
		out.TodayCompletions = []todayCompletion{}
		return
	}

	// Dedup by normalized title: MCP complete_task and Notion webhook both
	// create activity events for the same completion. Keep only the first.
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

// isCompletionEvent checks if an activity event represents a task completion.
// MCP: event_type=task_completed
// Notion: event_type=task_status_change with status=Done in metadata
func isCompletionEvent(eventType, source string, metadata json.RawMessage) bool {
	if eventType == "task_completed" {
		return true
	}
	if eventType == "task_status_change" && source == "notion" {
		var meta map[string]string
		if json.Unmarshal(metadata, &meta) == nil {
			return meta["status"] == "Done"
		}
	}
	return false
}

// parseDailyMetrics extracts daily metrics from a session note's metadata.
func parseDailyMetrics(n *session.Note) *dailyMetrics {
	if len(n.Metadata) == 0 {
		return nil
	}
	var meta struct {
		TasksPlanned            int     `json:"tasks_planned"`
		TasksCompleted          int     `json:"tasks_completed"`
		TasksCommitted          int     `json:"tasks_committed"`
		TasksPulled             int     `json:"tasks_pulled"`
		CompletionRate          float64 `json:"completion_rate"`
		CommittedCompletionRate float64 `json:"committed_completion_rate"`
		EnergyPattern           string  `json:"energy_pattern"`
	}
	if err := json.Unmarshal(n.Metadata, &meta); err != nil {
		return nil // best-effort: skip notes with unparseable metadata
	}
	return &dailyMetrics{
		Date:                    n.NoteDate.Format(time.DateOnly),
		TasksPlanned:            meta.TasksPlanned,
		TasksCompleted:          meta.TasksCompleted,
		TasksCommitted:          meta.TasksCommitted,
		TasksPulled:             meta.TasksPulled,
		CompletionRate:          meta.CompletionRate,
		CommittedCompletionRate: meta.CommittedCompletionRate,
		EnergyPattern:           meta.EnergyPattern,
	}
}

// buildPlanningHistory aggregates metrics notes into a planning history summary.
// recentDays controls how many entries are included in Entries (the rest feed monthly summary).
func buildPlanningHistory(notes []session.Note, recentDays int) planningHistorySummary {
	allEntries := make([]dailyMetrics, 0, len(notes))
	for i := range notes {
		if dm := parseDailyMetrics(&notes[i]); dm != nil {
			allEntries = append(allEntries, *dm)
		}
	}

	// Cap recent entries
	recentEntries := allEntries
	if len(recentEntries) > recentDays {
		recentEntries = recentEntries[:recentDays]
	}

	summary := planningHistorySummary{
		Days:              recentDays,
		Entries:           recentEntries,
		CapacityByDayType: make(map[string]float64),
	}

	if len(allEntries) == 0 {
		summary.Trend = "no_data"
		return summary
	}

	// Recent averages (from capped entries)
	var totalRate, totalCommitted, totalCapacity float64
	for _, e := range recentEntries {
		totalRate += e.CompletionRate
		totalCommitted += e.CommittedCompletionRate
		totalCapacity += float64(e.TasksCompleted)
	}
	n := float64(len(recentEntries))
	summary.AvgCompletionRate = totalRate / n
	summary.AvgCommittedRate = totalCommitted / n
	summary.AvgDailyCapacity = totalCapacity / n
	summary.Trend = computeTrend(recentEntries)

	// F6: Capacity by day type + variance (from ALL entries)
	summary.CapacityByDayType, summary.CapacityVariance = computeCapacityMetrics(allEntries)

	// F4: Monthly summary (from ALL entries, only if more data than recent window)
	if len(allEntries) > recentDays {
		summary.MonthlySummary = computeMonthlySummary(allEntries, summary.CapacityByDayType)
	}

	return summary
}

// computeCapacityMetrics calculates per-weekday capacity averages and overall variance.
func computeCapacityMetrics(entries []dailyMetrics) (byDay map[string]float64, variance float64) {
	byDay = make(map[string]float64)
	dayCounts := make(map[string]int)

	var allCapacities []float64
	for _, e := range entries {
		capacity := float64(e.TasksCompleted)
		allCapacities = append(allCapacities, capacity)

		d, err := time.Parse(time.DateOnly, e.Date)
		if err != nil {
			continue
		}
		day := strings.ToLower(d.Weekday().String())
		byDay[day] += capacity
		dayCounts[day]++
	}

	// Average per day type
	for day, total := range byDay {
		byDay[day] = total / float64(dayCounts[day])
	}

	// Add weekday_avg and weekend_avg
	var weekdaySum float64
	var weekdayCount int
	var weekendSum float64
	var weekendCount int
	for day, avg := range byDay {
		switch day {
		case "saturday", "sunday":
			weekendSum += avg
			weekendCount++
		default:
			weekdaySum += avg
			weekdayCount++
		}
	}
	if weekdayCount > 0 {
		byDay["weekday_avg"] = weekdaySum / float64(weekdayCount)
	}
	if weekendCount > 0 {
		byDay["weekend_avg"] = weekendSum / float64(weekendCount)
	}

	// Variance (population)
	if len(allCapacities) > 1 {
		mean := 0.0
		for _, c := range allCapacities {
			mean += c
		}
		mean /= float64(len(allCapacities))
		var sumSq float64
		for _, c := range allCapacities {
			diff := c - mean
			sumSq += diff * diff
		}
		variance = sumSq / float64(len(allCapacities))
	}

	return byDay, variance
}

// computeMonthlySummary aggregates all entries into a monthly overview.
func computeMonthlySummary(entries []dailyMetrics, capacityByDay map[string]float64) *monthlySummary {
	var totalRate, totalCapacity float64
	for _, e := range entries {
		totalRate += e.CompletionRate
		totalCapacity += float64(e.TasksCompleted)
	}
	n := float64(len(entries))

	ms := &monthlySummary{
		TotalDaysTracked:  len(entries),
		AvgCompletionRate: totalRate / n,
		AvgDailyCapacity:  totalCapacity / n,
	}

	// Best/worst day type (exclude aggregated keys)
	var bestDay, worstDay string
	bestCap := -1.0
	worstCap := 1e9
	for day, avg := range capacityByDay {
		if day == "weekday_avg" || day == "weekend_avg" {
			continue
		}
		if avg > bestCap {
			bestCap = avg
			bestDay = day
		}
		if avg < worstCap {
			worstCap = avg
			worstDay = day
		}
	}
	ms.BestDayType = bestDay
	ms.WorstDayType = worstDay

	return ms
}

// computeTrend compares the average completion rate of the most recent 3 entries
// against the older entries. Returns "up", "stable", or "down".
func computeTrend(entries []dailyMetrics) string {
	if len(entries) < 4 {
		return "insufficient_data"
	}

	// entries are ordered by date desc (most recent first)
	recentCount := 3
	if recentCount > len(entries) {
		recentCount = len(entries)
	}
	olderStart := recentCount

	var recentSum, olderSum float64
	for i := range recentCount {
		recentSum += entries[i].CompletionRate
	}
	for i := olderStart; i < len(entries); i++ {
		olderSum += entries[i].CompletionRate
	}

	recentAvg := recentSum / float64(recentCount)
	olderAvg := olderSum / float64(len(entries)-olderStart)

	diff := recentAvg - olderAvg
	switch {
	case diff > 0.1:
		return "up"
	case diff < -0.1:
		return "down"
	default:
		return "stable"
	}
}

// computeSkipCount estimates how many cycles a task has been pushed back.
func computeSkipCount(overdueDays int, isRecurring bool, recurInterval *int32) int {
	if overdueDays < 1 {
		return 0
	}
	if isRecurring && recurInterval != nil && *recurInterval > 0 {
		return overdueDays / int(*recurInterval)
	}
	if overdueDays >= 7 {
		return overdueDays / 7
	}
	return 0
}

// isProjectNeglected checks if a project's inactivity exceeds its expected cadence.
func isProjectNeglected(daysSinceActivity int, cadence string) bool {
	cadenceDays := map[string]int{
		"daily": 2, "weekly": 10, "biweekly": 21, "monthly": 45, "on_hold": 9999,
	}
	maxDays, ok := cadenceDays[cadence]
	if !ok {
		maxDays = 10 // default weekly
	}
	return daysSinceActivity > maxDays
}

// parseAdjustments extracts the adjustments array from metrics metadata.
func parseAdjustments(metadata json.RawMessage) []string {
	if len(metadata) == 0 {
		return nil
	}
	var meta struct {
		Adjustments []string `json:"adjustments"`
	}
	if err := json.Unmarshal(metadata, &meta); err != nil || len(meta.Adjustments) == 0 {
		return nil
	}
	return meta.Adjustments
}

// parseInsightBrief extracts a brief insight summary from a session note.
func parseInsightBrief(n *session.Note) insightBrief {
	brief := insightBrief{
		ID:        n.ID,
		CreatedAt: n.CreatedAt.Format(time.DateOnly),
	}

	if len(n.Metadata) == 0 {
		return brief
	}

	var meta struct {
		Hypothesis string `json:"hypothesis"`
		Status     string `json:"status"`
		Project    string `json:"project"`
	}
	if err := json.Unmarshal(n.Metadata, &meta); err != nil {
		return brief
	}

	brief.Hypothesis = meta.Hypothesis
	brief.Status = meta.Status
	brief.Project = meta.Project
	return brief
}
