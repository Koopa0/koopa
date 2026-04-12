package admin

import (
	"context"
	"net/http"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/learning"
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
		CompletionRateLastWeek int `json:"completion_rate_last_week"`
	} `json:"plan_adherence"`
	GoalHealth struct {
		OnTrack int `json:"on_track"`
		AtRisk  int `json:"at_risk"`
		Stalled int `json:"stalled"`
	} `json:"goal_health"`
	Learning struct {
		SessionsThisWeek int `json:"sessions_this_week"`
		WeaknessCount    int `json:"weakness_count"`
		WeaknessChange   int `json:"weakness_change"`
		MasteryCount     int `json:"mastery_count"`
		MasteryChange    int `json:"mastery_change"`
		ReviewBacklog    int `json:"review_backlog"`
	} `json:"learning"`
	Content struct {
		PublishedThisMonth int `json:"published_this_month"`
		PublishedTarget    int `json:"published_target"`
		DraftsInProgress   int `json:"drafts_in_progress"`
	} `json:"content"`
	InboxHealth struct {
		CurrentCount      int `json:"current_count"`
		WeekStartCount    int `json:"week_start_count"`
		ClarifiedThisWeek int `json:"clarified_this_week"`
		CapturedThisWeek  int `json:"captured_this_week"`
	} `json:"inbox_health"`
	SomedayHealth struct {
		Total      int `json:"total"`
		StaleCount int `json:"stale_count"`
	} `json:"someday_health"`
	DirectiveHealth struct {
		OpenCount         int `json:"open_count"`
		AvgResolutionDays int `json:"avg_resolution_days"`
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
	lastWeekStart := weekStart.AddDate(0, 0, -7)

	planRate := func(start, end time.Time) int {
		planned, done := 0, 0
		for d := start; d.Before(end); d = d.AddDate(0, 0, 1) {
			items, err := h.dayplan.ItemsByDate(ctx, d)
			if err != nil {
				continue
			}
			planned += len(items)
			for j := range items {
				if items[j].Status == "done" {
					done++
				}
			}
		}
		if planned == 0 {
			return 0
		}
		return done * 100 / planned
	}

	out.PlanAdherence.CompletionRateThisWeek = planRate(weekStart, now)
	out.PlanAdherence.CompletionRateLastWeek = planRate(lastWeekStart, weekStart)
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
	// Weakness and mastery counts from concept observations (last 90 days).
	since90 := now.AddDate(0, -3, 0)
	if rows, err := h.learn.WeaknessAnalysis(ctx, nil, since90, "high"); err == nil {
		out.Learning.WeaknessCount = len(rows)
	}
	if rows, err := h.learn.ConceptMastery(ctx, nil, since90, "high"); err == nil {
		for i := range rows {
			stage := learning.DeriveMasteryStage(rows[i].WeaknessCount, rows[i].ImprovementCount, rows[i].MasteryCount)
			if stage == learning.StageSolid {
				out.Learning.MasteryCount++
			}
		}
	}
	// WeaknessChange and MasteryChange require historical snapshots — return 0 for now.
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
	now := time.Now()
	thisWeekStart := now.AddDate(0, 0, -int(now.Weekday()-time.Monday))
	thisWeekStart = time.Date(thisWeekStart.Year(), thisWeekStart.Month(), thisWeekStart.Day(), 0, 0, 0, 0, h.loc)

	if n, err := h.tasks.InboxCount(ctx); err == nil {
		out.InboxHealth.CurrentCount = n
	}
	// CapturedThisWeek: tasks created since Monday (all statuses — a capture is any new task).
	if created, err := h.tasks.TasksCreatedSince(ctx, thisWeekStart); err == nil {
		out.InboxHealth.CapturedThisWeek = len(created)
	}
	// WeekStartCount and ClarifiedThisWeek require historical snapshots — zero for now.

	if n, err := h.tasks.StaleSomedayCount(ctx, 30); err == nil {
		out.SomedayHealth.StaleCount = n
	}

	if dirs, err := h.directives.OpenDirectives(ctx); err == nil {
		out.DirectiveHealth.OpenCount = len(dirs)
	}
	// AvgResolutionDays: mean days between issued_date and resolved_at.
	if resolved, err := h.directives.ResolvedDirectivesRecent(ctx); err == nil && len(resolved) > 0 {
		total := 0
		for i := range resolved {
			if resolved[i].ResolvedAt != nil {
				total += int(resolved[i].ResolvedAt.Sub(resolved[i].IssuedDate).Hours() / 24)
			}
		}
		out.DirectiveHealth.AvgResolutionDays = total / len(resolved)
	}
}
