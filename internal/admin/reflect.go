package admin

import (
	"net/http"
	"time"

	agentnote "github.com/Koopa0/koopa0.dev/internal/agent/note"
	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/daily"
	"github.com/Koopa0/koopa0.dev/internal/hypothesis"
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

	// Completed todo items.
	if todos, err := h.todos.CompletedItemsDetailSince(ctx, date); err == nil {
		endOfDay := date.AddDate(0, 0, 1)
		for i := range todos {
			if todos[i].CompletedAt != nil && todos[i].CompletedAt.Before(endOfDay) {
				out.CompletedTasks = append(out.CompletedTasks, completedTask{
					ID:    todos[i].ID.String(),
					Title: todos[i].Title,
					Area:  todos[i].ProjectTitle,
				})
			}
		}
	}

	// Learning sessions.
	endOfDay := date.AddDate(0, 0, 1)
	if sessions, err := h.learn.RecentSessions(ctx, nil, date, 20); err == nil {
		for i := range sessions {
			s := &sessions[i]
			if s.StartedAt.Before(endOfDay) {
				dur := 0
				var endedAt string
				if s.EndedAt != nil {
					dur = int(s.EndedAt.Sub(s.StartedAt).Minutes())
					endedAt = s.EndedAt.Format(time.RFC3339)
				}
				out.LearningSessions = append(out.LearningSessions, map[string]any{
					"id":               s.ID.String(),
					"domain":           s.Domain,
					"mode":             string(s.Mode),
					"started_at":       s.StartedAt.Format(time.RFC3339),
					"ended_at":         endedAt,
					"duration_minutes": dur,
					"attempts_count":   0,
					"solved_count":     0,
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

	type projectHealthItem struct {
		Title          string `json:"title"`
		Status         string `json:"status"`
		TasksCompleted int    `json:"tasks_completed"`
		Stalled        bool   `json:"stalled"`
	}

	type resp struct {
		WeekStart       string              `json:"week_start"`
		WeekEnd         string              `json:"week_end"`
		GoalProgress    []any               `json:"goal_progress"`
		ProjectHealth   []projectHealthItem `json:"project_health"`
		LearningSummary struct {
			SessionsCount    int      `json:"sessions_count"`
			TotalMinutes     int      `json:"total_minutes"`
			ConceptsImproved []string `json:"concepts_improved"`
			ConceptsDeclined []string `json:"concepts_declined"`
		} `json:"learning_summary"`
		ContentOutput struct {
			Published int `json:"published"`
			Drafted   int `json:"drafted"`
		} `json:"content_output"`
		InboxHealth struct {
			StartCount int `json:"start_count"`
			EndCount   int `json:"end_count"`
			Clarified  int `json:"clarified"`
			Captured   int `json:"captured"`
		} `json:"inbox_health"`
		InsightsNeedingCheck []any `json:"insights_needing_check"`
		Metrics              struct {
			TasksCompleted int `json:"tasks_completed"`
			Commits        int `json:"commits"`
			BuildLogs      int `json:"build_logs"`
		} `json:"metrics"`
	}

	out := resp{
		WeekStart:            weekStart.Format(time.DateOnly),
		WeekEnd:              weekEnd.Format(time.DateOnly),
		GoalProgress:         []any{},
		ProjectHealth:        []projectHealthItem{},
		InsightsNeedingCheck: []any{},
	}
	out.LearningSummary.ConceptsImproved = []string{}
	out.LearningSummary.ConceptsDeclined = []string{}

	// Goal progress.
	if goals, err := h.goals.ActiveGoals(ctx); err == nil {
		for i := range goals {
			g := &goals[i]
			out.GoalProgress = append(out.GoalProgress, map[string]any{
				"goal_title":                     g.Title,
				"milestones_completed_this_week": g.MilestoneDone,
				"total_done":                     g.MilestoneDone,
				"total":                          g.MilestoneTotal,
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

	// Todo completions.
	if todos, err := h.todos.CompletedItemsDetailSince(ctx, weekStart); err == nil {
		for i := range todos {
			if todos[i].CompletedAt != nil && todos[i].CompletedAt.Before(weekEnd) {
				out.Metrics.TasksCompleted++
			}
		}
	}

	// Hypotheses needing check (was: insights).
	if records, err := h.hypotheses.Unverified(ctx, 20); err == nil {
		for i := range records {
			ageDays := int(time.Since(records[i].CreatedAt).Hours() / 24)
			rec := &records[i]
			evidenceCount := 0
			if ev, ok := rec.Metadata["evidence"].([]any); ok {
				evidenceCount = len(ev)
			}
			out.InsightsNeedingCheck = append(out.InsightsNeedingCheck, map[string]any{
				"id":                     rec.ID,
				"hypothesis":             rec.Claim,
				"invalidation_condition": rec.InvalidationCondition,
				"status":                 string(rec.State),
				"source":                 rec.Author,
				"observed_date":          rec.ObservedDate.Format(time.DateOnly),
				"age_days":               ageDays,
				"evidence_count":         evidenceCount,
			})
		}
	}

	api.Encode(w, http.StatusOK, out)
}

// JournalList handles GET /api/admin/reflect/journal.
//
// TODO(coordination-rebuild): rename endpoint to /api/admin/reflect/notes
// once the admin frontend catches up. Keeping the URL path stable during
// the rebuild so the frontend dispatch does not break.
func (h *Handler) JournalList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	kindRaw := q.Get("kind")
	since := h.today().AddDate(0, -1, 0)

	var kindPtr *agentnote.Kind
	var sourcePtr *string
	if kindRaw != "" {
		k := agentnote.Kind(kindRaw)
		kindPtr = &k
	}

	notes, err := h.notes.NotesInRange(ctx, since, time.Now(), kindPtr, sourcePtr)
	if err != nil {
		h.logger.Error("notes list", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}
	if notes == nil {
		notes = []agentnote.Note{}
	}

	api.Encode(w, http.StatusOK, notes)
}

// InsightsList handles GET /api/admin/reflect/insights.
//
// TODO(coordination-rebuild): rename endpoint path to /api/admin/reflect/hypotheses
// once the admin frontend catches up. Kept under the old URL during the rebuild.
func (h *Handler) InsightsList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stateRaw := r.URL.Query().Get("status")
	var statePtr *hypothesis.State
	if stateRaw != "" {
		s := hypothesis.State(stateRaw)
		statePtr = &s
	}

	records, err := h.hypotheses.ByState(ctx, statePtr, 50)
	if err != nil {
		h.logger.Error("hypotheses list", "error", err)
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

	result := make([]insightSummary, len(records))
	for i := range records {
		rec := &records[i]
		evidenceCount := 0
		if ev, ok := rec.Metadata["evidence"].([]any); ok {
			evidenceCount = len(ev)
		}
		result[i] = insightSummary{
			ID:                    rec.ID,
			Hypothesis:            rec.Claim,
			InvalidationCondition: rec.InvalidationCondition,
			Status:                string(rec.State),
			Source:                rec.Author,
			ObservedDate:          rec.ObservedDate.Format(time.DateOnly),
			AgeDays:               int(time.Since(rec.CreatedAt).Hours() / 24),
			EvidenceCount:         evidenceCount,
		}
	}

	api.Encode(w, http.StatusOK, result)
}
