package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/session"
)

// MorningContextInput is the input for the get_morning_context tool.
type MorningContextInput struct {
	ActivityDays int `json:"activity_days,omitempty" jsonschema_description:"days of activity to include (default 3)"`
	BuildLogDays int `json:"build_log_days,omitempty" jsonschema_description:"days of build logs to include (default 7)"`
}

// MorningContextOutput is the aggregated output for daily planning.
type MorningContextOutput struct {
	Date                string                 `json:"date"`
	OverdueTasks        []morningTask          `json:"overdue_tasks"`
	TodayTasks          []morningTask          `json:"today_tasks"`
	UpcomingTasks       []morningTask          `json:"upcoming_tasks"`
	MyDayTasks          []morningTask          `json:"my_day_tasks"`
	RecentActivity      activitySummary        `json:"recent_activity"`
	RecentBuildLogs     []buildLogBrief        `json:"recent_build_logs"`
	Projects            []projectHealth        `json:"projects"`
	Goals               []goalBrief            `json:"goals"`
	YesterdayReflection string                 `json:"yesterday_reflection,omitempty"`
	PlanningHistory     planningHistorySummary `json:"planning_history"`
	ActiveInsights      []insightBrief         `json:"active_insights"`
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
	Days             int            `json:"days"`
	Entries          []dailyMetrics `json:"entries"`
	AvgCompletionRate float64       `json:"avg_completion_rate"`
	AvgCommittedRate  float64       `json:"avg_committed_rate"`
	AvgDailyCapacity  float64       `json:"avg_daily_capacity"`
	Trend            string         `json:"trend"`
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

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	tomorrow := today.AddDate(0, 0, 1)
	weekEnd := today.AddDate(0, 0, 7)

	out := MorningContextOutput{
		Date: now.Format("2006-01-02 (Monday)"),
	}

	// --- Tasks (all pending, sorted by deadline) ---
	allTasks, err := s.tasks.PendingTasksWithProject(ctx, nil, 100)
	if err != nil {
		s.logger.Error("morning_context: pending tasks", "error", err)
	} else {
		for _, t := range allTasks {
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
	}

	// Ensure non-nil slices for JSON
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

	// --- Activity summary ---
	actStart := now.AddDate(0, 0, -activityDays)
	events, err := s.activity.EventsByFilters(ctx, actStart, now, nil, nil, 200)
	if err != nil {
		s.logger.Error("morning_context: activity", "error", err)
	} else {
		summary := activitySummary{
			Period:    fmt.Sprintf("last %d days", activityDays),
			BySource:  make(map[string]int),
			ByProject: make(map[string]int),
		}
		for _, e := range events {
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

	// --- Build logs (recent content type=build-log, slim for morning planning) ---
	buildLogStart := now.AddDate(0, 0, -buildLogDays)
	buildLogs, err := s.contents.RecentByType(ctx, "build-log", buildLogStart, 3)
	if err != nil {
		s.logger.Error("morning_context: build logs", "error", err)
	}
	out.RecentBuildLogs = make([]buildLogBrief, 0, len(buildLogs))
	for _, c := range buildLogs {
		out.RecentBuildLogs = append(out.RecentBuildLogs, buildLogBrief{
			Slug:        c.Slug,
			Title:       c.Title,
			Project:     extractFrontmatter(c.Body, "project"),
			SessionType: extractFrontmatter(c.Body, "session_type"),
			CreatedAt:   c.CreatedAt.Format(time.DateOnly),
		})
	}

	// --- Project health ---
	projects, err := s.projects.ActiveProjects(ctx)
	if err != nil {
		s.logger.Error("morning_context: projects", "error", err)
	} else {
		// Count pending tasks per project
		tasksByProject := make(map[string]int)
		for _, t := range allTasks {
			if t.ProjectSlug != "" {
				tasksByProject[t.ProjectSlug]++
			}
		}

		out.Projects = make([]projectHealth, 0, len(projects))
		for _, p := range projects {
			ph := projectHealth{
				Slug:         p.Slug,
				Title:        p.Title,
				Status:       string(p.Status),
				PendingTasks: tasksByProject[p.Slug],
			}
			if p.LastActivityAt != nil {
				ph.DaysSinceActivity = int(now.Sub(*p.LastActivityAt).Hours() / 24)
			}
			out.Projects = append(out.Projects, ph)
		}
	}

	// --- Goals ---
	goals, err := s.goals.Goals(ctx)
	if err != nil {
		s.logger.Error("morning_context: goals", "error", err)
	} else {
		out.Goals = make([]goalBrief, 0)
		for _, g := range goals {
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

	// --- Session notes (yesterday reflection + planning history + active insights) ---
	if s.sessionReader != nil {
		refl, reflErr := s.sessionReader.LatestNoteByType(ctx, "reflection")
		if reflErr != nil {
			s.logger.Error("morning_context: yesterday reflection", "error", reflErr)
		} else {
			out.YesterdayReflection = refl.Content
		}

		since := now.AddDate(0, 0, -7)
		metricsNotes, metricsErr := s.sessionReader.MetricsHistory(ctx, since)
		if metricsErr != nil {
			s.logger.Error("morning_context: planning history", "error", metricsErr)
		}
		out.PlanningHistory = buildPlanningHistory(metricsNotes, 7)

		// Active insights (unverified, most recent 5)
		unverified := "unverified"
		insightNotes, insightErr := s.sessionReader.InsightsByStatus(ctx, &unverified, nil, 5)
		if insightErr != nil {
			s.logger.Error("morning_context: active insights", "error", insightErr)
		}
		out.ActiveInsights = make([]insightBrief, 0, len(insightNotes))
		for i := range insightNotes {
			out.ActiveInsights = append(out.ActiveInsights, parseInsightBrief(&insightNotes[i]))
		}
	}
	if out.PlanningHistory.Entries == nil {
		out.PlanningHistory.Entries = []dailyMetrics{}
	}
	if out.ActiveInsights == nil {
		out.ActiveInsights = []insightBrief{}
	}

	return nil, out, nil
}

// parseDailyMetrics extracts daily metrics from a session note's metadata.
func parseDailyMetrics(n session.Note) *dailyMetrics {
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
func buildPlanningHistory(notes []session.Note, days int) planningHistorySummary {
	entries := make([]dailyMetrics, 0, len(notes))
	for _, n := range notes {
		if dm := parseDailyMetrics(n); dm != nil {
			entries = append(entries, *dm)
		}
	}

	summary := planningHistorySummary{
		Days:    days,
		Entries: entries,
	}

	if len(entries) == 0 {
		summary.Trend = "no_data"
		return summary
	}

	// Calculate averages
	var totalRate, totalCommitted, totalCapacity float64
	for _, e := range entries {
		totalRate += e.CompletionRate
		totalCommitted += e.CommittedCompletionRate
		totalCapacity += float64(e.TasksCompleted)
	}
	n := float64(len(entries))
	summary.AvgCompletionRate = totalRate / n
	summary.AvgCommittedRate = totalCommitted / n
	summary.AvgDailyCapacity = totalCapacity / n

	// Trend: compare recent 3 days vs older entries
	summary.Trend = computeTrend(entries)

	return summary
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
