package admin

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/api"
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
	req, err := api.Decode[PlanDayRequest](w, r)
	if err != nil {
		return
	}
	if len(req.Items) == 0 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "items is required")
		return
	}

	ctx := r.Context()
	date := h.today()

	for _, item := range req.Items {
		taskID, parseErr := uuid.Parse(item.TaskID)
		if parseErr != nil {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid task_id: "+item.TaskID)
			return
		}
		if _, uErr := h.dayplan.Upsert(ctx, &daily.UpsertParams{
			PlanDate:   date,
			TaskID:     taskID,
			SelectedBy: "human",
			Position:   int32(item.Position), //nolint:gosec // G115: position bounded by UI
		}); uErr != nil {
			h.logger.Error("today plan upsert", "task_id", taskID, "error", uErr)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
			return
		}
	}

	// Return updated plan.
	items, err := h.dayplan.ItemsByDate(ctx, date)
	if err != nil {
		h.logger.Error("today plan list", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	result := make([]PlanItemSummary, len(items))
	for i := range items {
		result[i] = planItemToSummary(&items[i], date)
	}
	api.Encode(w, http.StatusOK, map[string]any{
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
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid plan item id")
		return
	}

	req, err := api.Decode[ResolvePlanItemRequest](w, r)
	if err != nil {
		return
	}

	ctx := r.Context()

	switch req.Action {
	case "complete":
		if err := h.dayplan.Complete(ctx, itemID); err != nil {
			h.logger.Error("resolve plan item complete", "error", err)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
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
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
			return
		}

	case "drop":
		if err := h.dayplan.Drop(ctx, itemID); err != nil {
			h.logger.Error("resolve plan item drop", "error", err)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
			return
		}

	default:
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid action: must be complete, defer, or drop")
		return
	}

	api.Encode(w, http.StatusOK, map[string]string{"result": req.Action})
}
