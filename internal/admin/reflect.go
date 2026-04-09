package admin

import (
	"net/http"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/daily"
	"github.com/Koopa0/koopa0.dev/internal/journal"
)

// ReflectDaily handles GET /api/admin/reflect/daily?date=2026-04-08.
func (h *Handler) ReflectDaily(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	dateStr := r.URL.Query().Get("date")
	date := h.today()
	if dateStr != "" {
		if d, err := time.Parse(time.DateOnly, dateStr); err == nil {
			date = d
		}
	}

	type completedTask struct {
		ID    string `json:"id"`
		Title string `json:"title"`
		Area  string `json:"area,omitempty"`
	}

	type resp struct {
		Date         string `json:"date"`
		PlanVsActual struct {
			Planned   int `json:"planned"`
			Completed int `json:"completed"`
			Deferred  int `json:"deferred"`
			Dropped   int `json:"dropped"`
		} `json:"plan_vs_actual"`
		CompletedTasks   []completedTask `json:"completed_tasks"`
		LearningSessions []any           `json:"learning_sessions"`
		CommitsCount     int             `json:"commits_count"`
		InboxDelta       struct {
			Captured  int `json:"captured"`
			Clarified int `json:"clarified"`
			Net       int `json:"net"`
		} `json:"inbox_delta"`
	}

	out := resp{
		Date:             date.Format(time.DateOnly),
		CompletedTasks:   []completedTask{},
		LearningSessions: []any{},
	}

	// Plan vs actual from daily plan items.
	if items, err := h.dayplan.ItemsByDate(ctx, date); err == nil {
		out.PlanVsActual.Planned = len(items)
		for i := range items {
			switch items[i].Status {
			case daily.StatusDone:
				out.PlanVsActual.Completed++
			case daily.StatusDeferred:
				out.PlanVsActual.Deferred++
			case daily.StatusDropped:
				out.PlanVsActual.Dropped++
			case daily.StatusPlanned:
				// still planned = not yet resolved
			}
		}
	}

	// Completed tasks.
	if tasks, err := h.tasks.CompletedTasksDetailSince(ctx, date); err == nil {
		endOfDay := date.AddDate(0, 0, 1)
		for i := range tasks {
			if tasks[i].CompletedAt != nil && tasks[i].CompletedAt.Before(endOfDay) {
				out.CompletedTasks = append(out.CompletedTasks, completedTask{
					ID:    tasks[i].ID.String(),
					Title: tasks[i].Title,
					Area:  tasks[i].ProjectTitle,
				})
			}
		}
	}

	// Learning sessions.
	endOfDay := date.AddDate(0, 0, 1)
	if sessions, err := h.learn.RecentSessions(ctx, nil, date, 20); err == nil {
		for i := range sessions {
			if sessions[i].StartedAt.Before(endOfDay) {
				dur := 0
				if sessions[i].EndedAt != nil {
					dur = int(sessions[i].EndedAt.Sub(sessions[i].StartedAt).Minutes())
				}
				out.LearningSessions = append(out.LearningSessions, map[string]any{
					"domain":           sessions[i].Domain,
					"duration_minutes": dur,
				})
			}
		}
	}

	api.Encode(w, http.StatusOK, out)
}

// ReflectWeekly handles GET /api/admin/reflect/weekly?week_start=2026-04-01.
func (h *Handler) ReflectWeekly(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	weekStartStr := r.URL.Query().Get("week_start")
	weekStart := h.today().AddDate(0, 0, -int(h.today().Weekday()-time.Monday))
	if weekStartStr != "" {
		if d, err := time.Parse(time.DateOnly, weekStartStr); err == nil {
			weekStart = d
		}
	}
	weekEnd := weekStart.AddDate(0, 0, 7)

	type resp struct {
		WeekStart       string `json:"week_start"`
		WeekEnd         string `json:"week_end"`
		GoalProgress    []any  `json:"goal_progress"`
		LearningSummary struct {
			SessionsCount int `json:"sessions_count"`
			TotalMinutes  int `json:"total_minutes"`
		} `json:"learning_summary"`
		ContentOutput struct {
			Published int `json:"published"`
			Drafted   int `json:"drafted"`
		} `json:"content_output"`
		Metrics struct {
			TasksCompleted int `json:"tasks_completed"`
		} `json:"metrics"`
		InsightsNeedingCheck []any `json:"insights_needing_check"`
	}

	out := resp{
		WeekStart:            weekStart.Format(time.DateOnly),
		WeekEnd:              weekEnd.Format(time.DateOnly),
		GoalProgress:         []any{},
		InsightsNeedingCheck: []any{},
	}

	// Goal progress.
	if goals, err := h.goals.ActiveGoals(ctx); err == nil {
		for i := range goals {
			g := &goals[i]
			out.GoalProgress = append(out.GoalProgress, map[string]any{
				"goal_title":      g.Title,
				"milestones_done": g.MilestoneDone,
				"total":           g.MilestoneTotal,
				"status":          string(g.Status),
			})
		}
	}

	// Learning sessions this week.
	if sessions, err := h.learn.RecentSessions(ctx, nil, weekStart, 100); err == nil {
		for i := range sessions {
			if sessions[i].StartedAt.Before(weekEnd) {
				out.LearningSummary.SessionsCount++
				if sessions[i].EndedAt != nil {
					out.LearningSummary.TotalMinutes += int(sessions[i].EndedAt.Sub(sessions[i].StartedAt).Minutes())
				}
			}
		}
	}

	// Task completions.
	if tasks, err := h.tasks.CompletedTasksDetailSince(ctx, weekStart); err == nil {
		for i := range tasks {
			if tasks[i].CompletedAt != nil && tasks[i].CompletedAt.Before(weekEnd) {
				out.Metrics.TasksCompleted++
			}
		}
	}

	// Insights needing check.
	if insights, err := h.insights.Unverified(ctx, 20); err == nil {
		for i := range insights {
			ageDays := int(time.Since(insights[i].CreatedAt).Hours() / 24)
			out.InsightsNeedingCheck = append(out.InsightsNeedingCheck, map[string]any{
				"id":         insights[i].ID,
				"hypothesis": insights[i].Hypothesis,
				"status":     string(insights[i].Status),
				"age_days":   ageDays,
			})
		}
	}

	api.Encode(w, http.StatusOK, out)
}

// JournalWrite handles POST /api/admin/reflect/journal.
func (h *Handler) JournalWrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind string `json:"kind"`
		Body string `json:"body"`
		Date string `json:"date,omitempty"`
	}
	if req2, err := api.Decode[struct {
		Kind string `json:"kind"`
		Body string `json:"body"`
		Date string `json:"date,omitempty"`
	}](w, r); err != nil {
		return
	} else {
		req = req2
	}

	if req.Kind == "" || req.Body == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "kind and body are required")
		return
	}

	date := h.today()
	if req.Date != "" {
		if d, err := time.Parse(time.DateOnly, req.Date); err == nil {
			date = d
		}
	}

	entry, err := h.journal.Create(r.Context(), &journal.CreateParams{
		Kind:      journal.Kind(req.Kind),
		Source:    "human",
		Content:   req.Body,
		EntryDate: date,
	})
	if err != nil {
		h.logger.Error("journal write", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	api.Encode(w, http.StatusCreated, entry)
}

// JournalList handles GET /api/admin/reflect/journal.
func (h *Handler) JournalList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	kind := q.Get("kind")
	since := h.today().AddDate(0, -1, 0) // default: last month

	var kindPtr, sourcePtr *string
	if kind != "" {
		kindPtr = &kind
	}

	entries, err := h.journal.EntriesByDateRange(ctx, since, time.Now(), kindPtr, sourcePtr)
	if err != nil {
		h.logger.Error("journal list", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}
	if entries == nil {
		entries = []journal.Entry{}
	}

	api.Encode(w, http.StatusOK, map[string]any{"entries": entries})
}

// InsightsList handles GET /api/admin/reflect/insights.
func (h *Handler) InsightsList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	status := r.URL.Query().Get("status")
	var statusPtr *string
	if status != "" {
		statusPtr = &status
	}

	insights, err := h.insights.ByStatus(ctx, statusPtr, 50)
	if err != nil {
		h.logger.Error("insights list", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	type insightSummary struct {
		ID                    int64  `json:"id"`
		Hypothesis            string `json:"hypothesis"`
		InvalidationCondition string `json:"invalidation_condition"`
		Status                string `json:"status"`
		Source                string `json:"source"`
		ObservedDate          string `json:"observed_date"`
		AgeDays               int    `json:"age_days"`
		EvidenceCount         int    `json:"evidence_count"`
	}

	result := make([]insightSummary, len(insights))
	for i := range insights {
		ins := &insights[i]
		evidenceCount := 0
		if ev, ok := ins.Metadata["evidence"].([]any); ok {
			evidenceCount = len(ev)
		}
		result[i] = insightSummary{
			ID:                    ins.ID,
			Hypothesis:            ins.Hypothesis,
			InvalidationCondition: ins.InvalidationCondition,
			Status:                string(ins.Status),
			Source:                ins.Source,
			ObservedDate:          ins.ObservedDate.Format(time.DateOnly),
			AgeDays:               int(time.Since(ins.CreatedAt).Hours() / 24),
			EvidenceCount:         evidenceCount,
		}
	}

	api.Encode(w, http.StatusOK, map[string]any{"insights": result})
}
