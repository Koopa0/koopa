package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/daily"
)

// PlanDayRequest is the request body for POST /api/admin/today/plan.
type PlanDayRequest struct {
	Items []PlanDayItem `json:"items"`
}

// PlanDayItem represents a single task to add to today's plan.
type PlanDayItem struct {
	TaskID   string `json:"task_id"`
	Position int    `json:"position"`
}

// TodayPlan handles POST /api/admin/today/plan.
func (h *Handler) TodayPlan(w http.ResponseWriter, r *http.Request) {
	var req PlanDayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Items) == 0 {
		writeError(w, http.StatusBadRequest, "items is required")
		return
	}

	ctx := r.Context()
	date := h.today()

	for _, item := range req.Items {
		taskID, err := uuid.Parse(item.TaskID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid task_id: "+item.TaskID)
			return
		}
		if _, err := h.dayplan.Upsert(ctx, &daily.UpsertParams{
			PlanDate:   date,
			TaskID:     taskID,
			SelectedBy: "human",
			Position:   int32(item.Position), //nolint:gosec // G115: position bounded by UI
		}); err != nil {
			h.logger.Error("today plan upsert", "task_id", taskID, "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}

	// Return updated plan.
	items, err := h.dayplan.ItemsByDate(ctx, date)
	if err != nil {
		h.logger.Error("today plan list", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	result := make([]PlanItemSummary, len(items))
	for i := range items {
		result[i] = planItemToSummary(&items[i], date)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"date":  date.Format(time.DateOnly),
		"items": result,
	})
}

// ResolvePlanItemRequest is the request body for POST /api/admin/today/items/{id}/resolve.
type ResolvePlanItemRequest struct {
	Action string `json:"action"` // complete, defer, drop
}

// ResolvePlanItem handles POST /api/admin/today/items/{id}/resolve.
func (h *Handler) ResolvePlanItem(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	itemID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid plan item id")
		return
	}

	var req ResolvePlanItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()

	switch req.Action {
	case "complete":
		if err := h.dayplan.Complete(ctx, itemID); err != nil {
			h.logger.Error("resolve plan item complete", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		// Also complete the linked task.
		item, iErr := h.dayplan.ItemByID(ctx, itemID)
		if iErr == nil {
			now := time.Now()
			_ = h.tasks.Complete(ctx, item.TaskID, &now) // best-effort
		}

	case "defer":
		if err := h.dayplan.Defer(ctx, itemID); err != nil {
			h.logger.Error("resolve plan item defer", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

	case "drop":
		if err := h.dayplan.Drop(ctx, itemID); err != nil {
			h.logger.Error("resolve plan item drop", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

	default:
		writeError(w, http.StatusBadRequest, "invalid action: must be complete, defer, or drop")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"result": req.Action})
}
