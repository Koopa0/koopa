package admin

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/plan"
)

// LearnPlans handles GET /api/admin/learn/plans.
func (h *Handler) LearnPlans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	plans, err := h.plans.ActivePlans(ctx)
	if err != nil {
		h.logger.Error("learn plans list", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	type planSummary struct {
		ID             string `json:"id"`
		Title          string `json:"title"`
		Domain         string `json:"domain"`
		Status         string `json:"status"`
		ItemsTotal     int    `json:"items_total"`
		ItemsCompleted int    `json:"items_completed"`
		ItemsSkipped   int    `json:"items_skipped"`
		CreatedAt      string `json:"created_at"`
		UpdatedAt      string `json:"updated_at"`
	}

	result := make([]planSummary, 0, len(plans))
	for i := range plans {
		p := &plans[i]
		prog, _ := h.plans.Progress(ctx, p.ID)
		s := planSummary{
			ID:        p.ID.String(),
			Title:     p.Title,
			Domain:    p.Domain,
			Status:    string(p.Status),
			CreatedAt: p.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt: p.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
		if prog != nil {
			s.ItemsTotal = int(prog.Total)
			s.ItemsCompleted = int(prog.Completed)
			s.ItemsSkipped = int(prog.Skipped)
		}
		result = append(result, s)
	}

	api.Encode(w, http.StatusOK, map[string]any{"plans": result})
}

// LearnPlanDetail handles GET /api/admin/learn/plans/{id}.
func (h *Handler) LearnPlanDetail(w http.ResponseWriter, r *http.Request) {
	planID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid plan id")
		return
	}

	ctx := r.Context()

	p, err := h.plans.Plan(ctx, planID)
	if err != nil {
		h.logger.Error("learn plan detail", "error", err)
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "plan not found")
		return
	}

	items, _ := h.plans.Items(ctx, planID)
	if items == nil {
		items = []plan.PlanItem{}
	}

	prog, _ := h.plans.Progress(ctx, planID)

	api.Encode(w, http.StatusOK, map[string]any{
		"id":          p.ID.String(),
		"title":       p.Title,
		"domain":      p.Domain,
		"status":      string(p.Status),
		"description": p.Description,
		"items":       items,
		"progress":    prog,
	})
}

// LearnPlanAddItems handles POST /api/admin/learn/plans/{id}/items.
func (h *Handler) LearnPlanAddItems(w http.ResponseWriter, r *http.Request) {
	planID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid plan id")
		return
	}

	var req struct {
		ItemIDs []string `json:"item_ids"`
	}
	if req2, dErr := api.Decode[struct {
		ItemIDs []string `json:"item_ids"`
	}](w, r); dErr != nil {
		return
	} else {
		req = req2
	}

	ctx := r.Context()
	for i, idStr := range req.ItemIDs {
		itemID, pErr := uuid.Parse(idStr)
		if pErr != nil {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid item_id: "+idStr)
			return
		}
		if _, aErr := h.plans.AddItem(ctx, plan.AddItemParams{
			PlanID:         planID,
			LearningItemID: itemID,
			Position:       int32(i)}); aErr != nil {
			h.logger.Error("plan add item", "error", aErr)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
			return
		}
	}

	api.Encode(w, http.StatusCreated, map[string]string{"result": "added"})
}

// LearnPlanRemoveItem handles DELETE /api/admin/learn/plans/{id}/items/{item_id}.
func (h *Handler) LearnPlanRemoveItem(w http.ResponseWriter, r *http.Request) {
	planID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid plan id")
		return
	}
	itemID, err := uuid.Parse(r.PathValue("item_id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid item id")
		return
	}

	if err := h.plans.RemoveItems(r.Context(), planID, []uuid.UUID{itemID}); err != nil {
		h.logger.Error("plan remove item", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	api.Encode(w, http.StatusOK, map[string]string{"result": "removed"})
}

// LearnPlanUpdateItem handles POST /api/admin/learn/plans/{id}/items/{item_id}/update.
func (h *Handler) LearnPlanUpdateItem(w http.ResponseWriter, r *http.Request) {
	_, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid plan id")
		return
	}
	itemID, err := uuid.Parse(r.PathValue("item_id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid item id")
		return
	}

	var req struct {
		Status string  `json:"status"`
		Reason *string `json:"reason,omitempty"`
	}
	if req2, dErr := api.Decode[struct {
		Status string  `json:"status"`
		Reason *string `json:"reason,omitempty"`
	}](w, r); dErr != nil {
		return
	} else {
		req = req2
	}

	params := plan.UpdateItemStatusParams{
		ID:     itemID,
		Status: plan.ItemStatus(req.Status),
		Reason: req.Reason,
	}

	item, err := h.plans.UpdateItemStatus(r.Context(), params)
	if err != nil {
		h.logger.Error("plan update item", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	api.Encode(w, http.StatusOK, item)
}

// LearnPlanReorder handles POST /api/admin/learn/plans/{id}/reorder.
func (h *Handler) LearnPlanReorder(w http.ResponseWriter, r *http.Request) {
	_, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid plan id")
		return
	}

	var req struct {
		ItemIDs []string `json:"item_ids"`
	}
	if req2, dErr := api.Decode[struct {
		ItemIDs []string `json:"item_ids"`
	}](w, r); dErr != nil {
		return
	} else {
		req = req2
	}

	ctx := r.Context()
	for i, idStr := range req.ItemIDs {
		itemID, pErr := uuid.Parse(idStr)
		if pErr != nil {
			continue
		}
		if uErr := h.plans.UpdateItemPosition(ctx, itemID, int32(i)); uErr != nil {
			h.logger.Warn("plan reorder", "item_id", idStr, "error", uErr)
		}
	}

	api.Encode(w, http.StatusOK, map[string]string{"result": "reordered"})
}

// LearnPlanUpdate handles PATCH /api/admin/learn/plans/{id}.
func (h *Handler) LearnPlanUpdate(w http.ResponseWriter, r *http.Request) {
	planID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid plan id")
		return
	}

	var req struct {
		Status *string `json:"status,omitempty"`
	}
	if req2, dErr := api.Decode[struct {
		Status *string `json:"status,omitempty"`
	}](w, r); dErr != nil {
		return
	} else {
		req = req2
	}

	ctx := r.Context()

	if req.Status != nil {
		updated, uErr := h.plans.UpdatePlanStatus(ctx, planID, plan.Status(*req.Status))
		if uErr != nil {
			h.logger.Error("plan update status", "error", uErr)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
			return
		}
		api.Encode(w, http.StatusOK, updated)
		return
	}

	api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "nothing to update")
}
