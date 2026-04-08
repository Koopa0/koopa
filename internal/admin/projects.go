package admin

import (
	"net/http"

	"github.com/google/uuid"
)

// ProjectsOverview handles GET /api/admin/plan/projects.
func (h *Handler) ProjectsOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "active"
	}

	projects, err := h.projects.ListByStatus(ctx, status)
	if err != nil {
		h.logger.Error("projects overview", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	type projectRow struct {
		ID             string `json:"id"`
		Title          string `json:"title"`
		Slug           string `json:"slug"`
		Status         string `json:"status"`
		Area           string `json:"area,omitempty"`
		GoalBreadcrumb any    `json:"goal_breadcrumb,omitempty"`
		StaleDays      int    `json:"staleness_days"`
		LastActivityAt string `json:"last_activity_at,omitempty"`
	}

	result := make([]projectRow, len(projects))
	for i := range projects {
		p := &projects[i]
		row := projectRow{
			ID:     p.ID.String(),
			Title:  p.Title,
			Slug:   p.Slug,
			Status: string(p.Status),
		}
		if p.LastActivityAt != nil {
			row.LastActivityAt = p.LastActivityAt.Format("2006-01-02T15:04:05Z07:00")
		}
		// Goal breadcrumb — only goal_id and goal_title (no milestone FK).
		if p.GoalID != nil {
			if g, gErr := h.goals.ByID(ctx, *p.GoalID); gErr == nil {
				row.GoalBreadcrumb = map[string]string{
					"goal_id":    g.ID.String(),
					"goal_title": g.Title,
				}
			}
		}
		result[i] = row
	}

	writeJSON(w, http.StatusOK, map[string]any{"projects": result})
}

// ProjectDetail handles GET /api/admin/plan/projects/{id}.
func (h *Handler) ProjectDetail(w http.ResponseWriter, r *http.Request) {
	projID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}

	ctx := r.Context()
	p, err := h.projects.ProjectByID(ctx, projID)
	if err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}

	resp := map[string]any{
		"id":          p.ID.String(),
		"title":       p.Title,
		"slug":        p.Slug,
		"description": p.Description,
		"status":      string(p.Status),
	}

	if p.GoalID != nil {
		if g, gErr := h.goals.ByID(ctx, *p.GoalID); gErr == nil {
			resp["goal_breadcrumb"] = map[string]string{
				"goal_id":    g.ID.String(),
				"goal_title": g.Title,
			}
		}
	}

	// Tasks by status.
	tasksByStatus, _ := h.tasks.TasksByProjectGrouped(ctx, projID)
	resp["tasks_by_status"] = tasksByStatus

	writeJSON(w, http.StatusOK, resp)
}
