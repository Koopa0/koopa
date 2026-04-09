package admin

import (
	"context"
	"net/http"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/api"
)

// trendResp is the response payload for GET /api/admin/dashboard/trends.
type trendResp struct {
	Period    string `json:"period"`
	Execution struct {
		TasksCompletedThisWeek int    `json:"tasks_completed_this_week"`
		TasksCompletedLastWeek int    `json:"tasks_completed_last_week"`
		Trend                  string `json:"trend"`
	} `json:"execution"`
	PlanAdherence struct {
		CompletionRateThisWeek int `json:"completion_rate_this_week"`
	} `json:"plan_adherence"`
	GoalHealth struct {
		OnTrack int `json:"on_track"`
		AtRisk  int `json:"at_risk"`
		Stalled int `json:"stalled"`
	} `json:"goal_health"`
	Learning struct {
		SessionsThisWeek int `json:"sessions_this_week"`
		ReviewBacklog    int `json:"review_backlog"`
	} `json:"learning"`
	Content struct {
		PublishedThisMonth int `json:"published_this_month"`
		DraftsInProgress   int `json:"drafts_in_progress"`
	} `json:"content"`
	InboxHealth struct {
		CurrentCount int `json:"current_count"`
	} `json:"inbox_health"`
	SomedayHealth struct {
		Total      int `json:"total"`
		StaleCount int `json:"stale_count"`
	} `json:"someday_health"`
	DirectiveHealth struct {
		OpenCount int `json:"open_count"`
	} `json:"directive_health"`
}

// DashboardTrends handles GET /api/admin/dashboard/trends.
func (h *Handler) DashboardTrends(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now()
	thisWeekStart := now.AddDate(0, 0, -int(now.Weekday()-time.Monday))
	thisWeekStart = time.Date(thisWeekStart.Year(), thisWeekStart.Month(), thisWeekStart.Day(), 0, 0, 0, 0, h.loc)
	lastWeekStart := thisWeekStart.AddDate(0, 0, -7)
	thisMonthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, h.loc)

	out := trendResp{
		Period: thisWeekStart.Format(time.DateOnly) + " ~ " + now.Format(time.DateOnly),
	}

	h.fillExecution(ctx, &out, lastWeekStart, thisWeekStart)
	h.fillPlanAdherence(ctx, &out, thisWeekStart, now)
	h.fillGoalHealth(ctx, &out)
	h.fillLearningTrends(ctx, &out, thisWeekStart, now)
	h.fillContentTrends(ctx, &out, thisMonthStart)
	h.fillHealthCounters(ctx, &out)

	api.Encode(w, http.StatusOK, out)
}

func (h *Handler) fillExecution(ctx context.Context, out *trendResp, lastWeekStart, thisWeekStart time.Time) {
	tasks, err := h.tasks.CompletedTasksDetailSince(ctx, lastWeekStart)
	if err != nil {
		return
	}
	for i := range tasks {
		if tasks[i].CompletedAt == nil {
			continue
		}
		if !tasks[i].CompletedAt.Before(thisWeekStart) {
			out.Execution.TasksCompletedThisWeek++
		} else {
			out.Execution.TasksCompletedLastWeek++
		}
	}
	switch {
	case out.Execution.TasksCompletedThisWeek > out.Execution.TasksCompletedLastWeek:
		out.Execution.Trend = "up"
	case out.Execution.TasksCompletedThisWeek < out.Execution.TasksCompletedLastWeek:
		out.Execution.Trend = "down"
	default:
		out.Execution.Trend = "flat"
	}
}

func (h *Handler) fillPlanAdherence(ctx context.Context, out *trendResp, weekStart, now time.Time) {
	totalPlanned, totalDone := 0, 0
	for d := weekStart; d.Before(now); d = d.AddDate(0, 0, 1) {
		items, err := h.dayplan.ItemsByDate(ctx, d)
		if err != nil {
			continue
		}
		totalPlanned += len(items)
		for j := range items {
			if items[j].Status == "done" {
				totalDone++
			}
		}
	}
	if totalPlanned > 0 {
		out.PlanAdherence.CompletionRateThisWeek = totalDone * 100 / totalPlanned
	}
}

func (h *Handler) fillGoalHealth(ctx context.Context, out *trendResp) {
	goals, err := h.goals.ActiveGoals(ctx)
	if err != nil {
		return
	}
	for i := range goals {
		g := &goals[i]
		atRisk := g.Deadline != nil &&
			time.Until(*g.Deadline).Hours() < 14*24 &&
			g.MilestoneTotal > 0 &&
			g.MilestoneDone*2 < g.MilestoneTotal
		if atRisk {
			out.GoalHealth.AtRisk++
		} else {
			out.GoalHealth.OnTrack++
		}
	}
}

func (h *Handler) fillLearningTrends(ctx context.Context, out *trendResp, weekStart, now time.Time) {
	if sessions, err := h.learn.RecentSessions(ctx, nil, weekStart, 100); err == nil {
		out.Learning.SessionsThisWeek = len(sessions)
	}
	if n, err := h.learn.DueReviewCount(ctx, now); err == nil {
		out.Learning.ReviewBacklog = n
	}
}

func (h *Handler) fillContentTrends(ctx context.Context, out *trendResp, monthStart time.Time) {
	contents, err := h.contents.RecentByType(ctx, "", monthStart, 100)
	if err != nil {
		return
	}
	for i := range contents {
		switch contents[i].Status { //nolint:exhaustive // only counting published+draft
		case "published":
			out.Content.PublishedThisMonth++
		case "draft":
			out.Content.DraftsInProgress++
		}
	}
}

func (h *Handler) fillHealthCounters(ctx context.Context, out *trendResp) {
	if n, err := h.tasks.InboxCount(ctx); err == nil {
		out.InboxHealth.CurrentCount = n
	}
	if n, err := h.tasks.StaleSomedayCount(ctx, 30); err == nil {
		out.SomedayHealth.StaleCount = n
	}
	if dirs, err := h.directives.OpenDirectives(ctx); err == nil {
		out.DirectiveHealth.OpenCount = len(dirs)
	}
}
