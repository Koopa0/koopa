package admin

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/daily"
	"github.com/Koopa0/koopa0.dev/internal/goal"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// TodayResponse is the aggregate payload for GET /api/admin/today.
type TodayResponse struct {
	Date                string             `json:"date"`
	ContextLine         string             `json:"context_line"`
	YesterdayUnfinished []PlanItemSummary  `json:"yesterday_unfinished"`
	TodayPlan           []PlanItemSummary  `json:"today_plan"`
	OverdueTasks        []TaskSummary      `json:"overdue_tasks"`
	NeedsAttention      NeedsAttention     `json:"needs_attention"`
	ReflectionContext   ReflectionCtx      `json:"reflection_context"`
	GoalPulse           []GoalPulseSummary `json:"goal_pulse"`
}

// PlanItemSummary is a daily plan item with denormalized task fields.
type PlanItemSummary struct {
	ID          string `json:"id"`
	TaskID      string `json:"task_id"`
	Title       string `json:"title"`
	Area        string `json:"area,omitempty"`
	Energy      string `json:"energy,omitempty"`
	Position    int    `json:"position"`
	Status      string `json:"status"`
	PlannedDate string `json:"planned_date"`
}

// TaskSummary is a lightweight task view for list endpoints.
type TaskSummary struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Status       string `json:"status"`
	Due          string `json:"due,omitempty"`
	Area         string `json:"area,omitempty"`
	Priority     string `json:"priority,omitempty"`
	Energy       string `json:"energy,omitempty"`
	ProjectTitle string `json:"project_title,omitempty"`
}

// NeedsAttention holds count-based attention signals.
type NeedsAttention struct {
	InboxCount        int `json:"inbox_count"`
	PendingDirectives int `json:"pending_directives"`
	UnreadReports     int `json:"unread_reports"`
	DueReviews        int `json:"due_reviews"`
	OverdueTasks      int `json:"overdue_tasks"`
	StaleSomedayCount int `json:"stale_someday_count"`
}

// ReflectionCtx provides yesterday's reflection context.
type ReflectionCtx struct {
	HasYesterdayReflection bool   `json:"has_yesterday_reflection"`
	ReflectionExcerpt      string `json:"reflection_excerpt,omitempty"`
}

// GoalPulseSummary is a lightweight goal view for the Today screen.
type GoalPulseSummary struct {
	ID              string `json:"id"`
	Title           string `json:"title"`
	Area            string `json:"area,omitempty"`
	Deadline        string `json:"deadline,omitempty"`
	DaysRemaining   *int   `json:"days_remaining,omitempty"`
	MilestonesTotal int    `json:"milestones_total"`
	MilestonesDone  int    `json:"milestones_done"`
	NextMilestone   string `json:"next_milestone,omitempty"`
	Status          string `json:"status"`
}

// Today handles GET /api/admin/today.
func (h *Handler) Today(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	date := h.today()

	resp := TodayResponse{
		Date: date.Format(time.DateOnly),
	}

	h.fillTodayPlan(ctx, date, &resp)
	h.fillYesterdayUnfinished(ctx, date, &resp)
	h.fillOverdueTasks(ctx, date, &resp)
	h.fillNeedsAttention(ctx, date, &resp)
	h.fillReflectionContext(ctx, date, &resp)
	h.fillGoalPulse(ctx, &resp)
	h.fillContextLine(ctx, date, &resp)

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) fillTodayPlan(ctx context.Context, date time.Time, resp *TodayResponse) {
	items, err := h.dayplan.ItemsByDate(ctx, date)
	if err != nil {
		h.logger.Warn("today: plan items", "error", err)
		return
	}
	resp.TodayPlan = make([]PlanItemSummary, len(items))
	for i := range items {
		resp.TodayPlan[i] = planItemToSummary(&items[i], date)
	}
}

func (h *Handler) fillYesterdayUnfinished(ctx context.Context, date time.Time, resp *TodayResponse) {
	yesterday := date.AddDate(0, 0, -1)
	items, err := h.dayplan.ItemsByDate(ctx, yesterday)
	if err != nil {
		h.logger.Warn("today: yesterday items", "error", err)
		return
	}
	for i := range items {
		if items[i].Status == daily.StatusPlanned {
			resp.YesterdayUnfinished = append(resp.YesterdayUnfinished, planItemToSummary(&items[i], yesterday))
		}
	}
	if resp.YesterdayUnfinished == nil {
		resp.YesterdayUnfinished = []PlanItemSummary{}
	}
}

func (h *Handler) fillOverdueTasks(ctx context.Context, date time.Time, resp *TodayResponse) {
	rows, err := h.tasks.OverdueTasks(ctx, date)
	if err != nil {
		h.logger.Warn("today: overdue tasks", "error", err)
		return
	}
	resp.OverdueTasks = make([]TaskSummary, len(rows))
	for i := range rows {
		resp.OverdueTasks[i] = pendingTaskToSummary(&rows[i])
	}
}

func (h *Handler) fillNeedsAttention(ctx context.Context, date time.Time, resp *TodayResponse) {
	na := &resp.NeedsAttention
	na.OverdueTasks = len(resp.OverdueTasks)

	if count, err := h.tasks.InboxCount(ctx); err == nil {
		na.InboxCount = count
	}
	if count, err := h.directives.UnackedCount(ctx); err == nil {
		na.PendingDirectives = count
	}
	if count, err := h.tasks.StaleSomedayCount(ctx, 30); err == nil {
		na.StaleSomedayCount = count
	}
	if count, err := h.learn.DueReviewCount(ctx, date); err == nil {
		na.DueReviews = count
	}
}

func (h *Handler) fillReflectionContext(ctx context.Context, date time.Time, resp *TodayResponse) {
	yesterday := date.AddDate(0, 0, -1)
	entries, err := h.journal.ReflectionForDate(ctx, yesterday)
	if err != nil || len(entries) == 0 {
		return
	}
	resp.ReflectionContext.HasYesterdayReflection = true
	excerpt := entries[0].Content
	if len(excerpt) > 200 {
		excerpt = excerpt[:200] + "..."
	}
	resp.ReflectionContext.ReflectionExcerpt = excerpt
}

func (h *Handler) fillGoalPulse(ctx context.Context, resp *TodayResponse) {
	goals, err := h.goals.ActiveGoals(ctx)
	if err != nil {
		h.logger.Warn("today: goals", "error", err)
		return
	}
	resp.GoalPulse = make([]GoalPulseSummary, len(goals))
	for i := range goals {
		resp.GoalPulse[i] = goalToSummary(&goals[i])
	}
}

func (h *Handler) fillContextLine(_ context.Context, date time.Time, resp *TodayResponse) {
	// Try to find the nearest-deadline active goal for context.
	if len(resp.GoalPulse) > 0 {
		for _, g := range resp.GoalPulse {
			if g.DaysRemaining != nil {
				resp.ContextLine = fmt.Sprintf("距離 %s 還有 %d 天", g.Title, *g.DaysRemaining)
				return
			}
		}
	}
	resp.ContextLine = fmt.Sprintf("今天是 %s", date.Format("2006-01-02 Monday"))
}

func planItemToSummary(item *daily.Item, date time.Time) PlanItemSummary {
	return PlanItemSummary{
		ID:          item.ID.String(),
		TaskID:      item.TaskID.String(),
		Title:       item.TaskTitle,
		Energy:      stringOrEmpty(item.TaskEnergy),
		Position:    int(item.Position),
		Status:      string(item.Status),
		PlannedDate: date.Format(time.DateOnly),
	}
}

func pendingTaskToSummary(t *task.PendingTaskDetail) TaskSummary {
	s := TaskSummary{
		ID:           t.ID.String(),
		Title:        t.Title,
		Status:       string(t.Status),
		Priority:     stringOrEmpty(t.Priority),
		Energy:       stringOrEmpty(t.Energy),
		ProjectTitle: t.ProjectTitle,
	}
	if t.Due != nil {
		s.Due = t.Due.Format(time.DateOnly)
	}
	return s
}

func goalToSummary(g *goal.ActiveGoalSummary) GoalPulseSummary {
	s := GoalPulseSummary{
		ID:              g.ID.String(),
		Title:           g.Title,
		Area:            g.AreaName,
		Status:          string(g.Status),
		MilestonesTotal: int(g.MilestoneTotal),
		MilestonesDone:  int(g.MilestoneDone),
	}
	if g.Deadline != nil {
		s.Deadline = g.Deadline.Format(time.DateOnly)
		days := int(time.Until(*g.Deadline).Hours() / 24)
		s.DaysRemaining = &days
	}
	return s
}

func stringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
