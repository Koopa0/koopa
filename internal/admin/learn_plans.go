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
