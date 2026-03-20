package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MorningContextInput is the input for the get_morning_context tool.
type MorningContextInput struct {
	ActivityDays int `json:"activity_days,omitempty" jsonschema_description:"days of activity to include (default 3)"`
	BuildLogDays int `json:"build_log_days,omitempty" jsonschema_description:"days of build logs to include (default 7)"`
}

// MorningContextOutput is the aggregated output for daily planning.
type MorningContextOutput struct {
	Date           string           `json:"date"`
	OverdueTasks   []morningTask    `json:"overdue_tasks"`
	TodayTasks     []morningTask    `json:"today_tasks"`
	UpcomingTasks  []morningTask    `json:"upcoming_tasks"`
	MyDayTasks     []morningTask    `json:"my_day_tasks"`
	RecentActivity activitySummary  `json:"recent_activity"`
	RecentBuildLogs []buildLogBrief `json:"recent_build_logs"`
	Projects       []projectHealth  `json:"projects"`
	Goals          []goalBrief      `json:"goals"`
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
	Slug      string `json:"slug"`
	Title     string `json:"title"`
	CreatedAt string `json:"created_at"`
	Excerpt   string `json:"excerpt"`
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

	// --- Build logs (recent content type=build-log) ---
	buildLogStart := now.AddDate(0, 0, -buildLogDays)
	buildLogs, err := s.contents.RecentByType(ctx, "build-log", buildLogStart, 10)
	if err != nil {
		s.logger.Error("morning_context: build logs", "error", err)
	}
	out.RecentBuildLogs = make([]buildLogBrief, 0, len(buildLogs))
	for _, c := range buildLogs {
		excerpt := c.Excerpt
		if excerpt == "" {
			excerpt = truncate(c.Body, 300)
		}
		out.RecentBuildLogs = append(out.RecentBuildLogs, buildLogBrief{
			Slug:      c.Slug,
			Title:     c.Title,
			CreatedAt: c.CreatedAt.Format(time.DateOnly),
			Excerpt:   excerpt,
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

	return nil, out, nil
}
