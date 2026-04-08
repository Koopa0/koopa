package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/db"
	"github.com/google/uuid"
)

// TasksBacklog handles GET /api/admin/plan/tasks.
func (h *Handler) TasksBacklog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	status := q.Get("status")
	if status == "" {
		status = "todo"
	}
	switch db.TaskStatus(status) {
	case db.TaskStatusInbox, db.TaskStatusTodo, db.TaskStatusInProgress,
		db.TaskStatusDone, db.TaskStatusSomeday:
		// valid
	default:
		if status != "all" {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid status")
			return
		}
	}
	projectID := q.Get("project_id")
	energy := q.Get("energy")
	priority := q.Get("priority")
	search := q.Get("search")
	limitStr := q.Get("limit")

	limit := 50
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}

	tasks, err := h.tasks.BacklogTasks(ctx, status, projectID, energy, priority, search, limit)
	if err != nil {
		h.logger.Error("tasks backlog", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	// Check which tasks are in today's plan.
	date := h.today()
	planItems, _ := h.dayplan.ItemsByDate(ctx, date)
	inPlan := map[uuid.UUID]bool{}
	for i := range planItems {
		inPlan[planItems[i].TaskID] = true
	}

	type taskRow struct {
		ID            string `json:"id"`
		Title         string `json:"title"`
		Status        string `json:"status"`
		Area          string `json:"area,omitempty"`
		Priority      string `json:"priority,omitempty"`
		Energy        string `json:"energy,omitempty"`
		Due           string `json:"due,omitempty"`
		ProjectTitle  string `json:"project_title,omitempty"`
		IsInTodayPlan bool   `json:"is_in_today_plan"`
	}

	result := make([]taskRow, len(tasks))
	for i := range tasks {
		t := &tasks[i]
		row := taskRow{
			ID:            t.ID.String(),
			Title:         t.Title,
			Status:        string(t.Status),
			ProjectTitle:  t.ProjectTitle,
			IsInTodayPlan: inPlan[t.ID],
		}
		if t.Priority != nil {
			row.Priority = *t.Priority
		}
		if t.Energy != nil {
			row.Energy = *t.Energy
		}
		if t.Due != nil {
			row.Due = t.Due.Format(time.DateOnly)
		}
		result[i] = row
	}

	api.Encode(w, http.StatusOK, map[string]any{
		"tasks": result,
		"meta":  map[string]int{"total": len(result)},
	})
}

// AdvanceTaskRequest is the request body for POST /api/admin/plan/tasks/{id}/advance.
type AdvanceTaskRequest struct {
	Action string `json:"action"` // start, complete, defer, drop
}

// AdvanceTask handles POST /api/admin/plan/tasks/{id}/advance.
func (h *Handler) AdvanceTask(w http.ResponseWriter, r *http.Request) {
	taskID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid task id")
		return
	}

	req, err := api.Decode[AdvanceTaskRequest](w, r)
	if err != nil {
		return
	}

	ctx := r.Context()

	switch req.Action {
	case "start":
		if err := h.tasks.Start(ctx, taskID); err != nil {
			h.logger.Error("advance task start", "error", err)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
			return
		}
	case "complete":
		now := time.Now()
		if err := h.tasks.Complete(ctx, taskID, &now); err != nil {
			h.logger.Error("advance task complete", "error", err)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
			return
		}
	case "defer":
		if err := h.tasks.DeferTask(ctx, taskID); err != nil {
			h.logger.Error("advance task defer", "error", err)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
			return
		}
	default:
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid action: must be start, complete, or defer. Use today/items/{id}/resolve for drop.")
		return
	}

	api.Encode(w, http.StatusOK, map[string]string{"result": req.Action})
}
