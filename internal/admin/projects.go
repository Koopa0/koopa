package admin

import (
	"errors"
	"net/http"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/db"
	"github.com/Koopa0/koopa0.dev/internal/project"
	"github.com/google/uuid"
)

// ProjectsOverview handles GET /api/admin/plan/projects.
func (h *Handler) ProjectsOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "active"
	}
	switch db.ProjectStatus(status) {
	case db.ProjectStatusPlanned, db.ProjectStatusInProgress, db.ProjectStatusOnHold,
		db.ProjectStatusCompleted, db.ProjectStatusMaintained, db.ProjectStatusArchived:
		// valid enum value
	default:
		if status != "active" && status != "all" {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid status filter")
			return
		}
	}

	projects, err := h.projects.ListByStatus(ctx, status)
	if err != nil {
		h.logger.Error("projects overview", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	type projectRow struct {
		ID             string       `json:"id"`
		Title          string       `json:"title"`
		Slug           string       `json:"slug"`
		Status         string       `json:"status"`
		Area           string       `json:"area,omitempty"`
		GoalBreadcrumb any          `json:"goal_breadcrumb,omitempty"`
		TaskProgress   TaskProgress `json:"task_progress"`
		StaleDays      int          `json:"staleness_days"`
		LastActivityAt string       `json:"last_activity_at,omitempty"`
	}

	// Batch fetch goal titles to avoid N+1.
	goalIDs := make([]uuid.UUID, 0, len(projects))
	for i := range projects {
		if projects[i].GoalID != nil {
			goalIDs = append(goalIDs, *projects[i].GoalID)
		}
	}
	goalTitles := map[uuid.UUID]string{}
	if len(goalIDs) > 0 {
		if goals, gErr := h.goals.ActiveGoals(ctx); gErr == nil {
			for i := range goals {
				goalTitles[goals[i].ID] = goals[i].Title
			}
		}
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
		if p.GoalID != nil {
			if title, ok := goalTitles[*p.GoalID]; ok {
				row.GoalBreadcrumb = map[string]string{
					"goal_id":    p.GoalID.String(),
					"goal_title": title,
				}
			}
		}
		result[i] = row
	}

	api.Encode(w, http.StatusOK, map[string]any{"projects": result})
}

// ProjectDetail handles GET /api/admin/plan/projects/{id}.
func (h *Handler) ProjectDetail(w http.ResponseWriter, r *http.Request) {
	projID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid project id")
		return
	}

	ctx := r.Context()
	p, err := h.projects.ProjectByID(ctx, projID)
	if errors.Is(err, project.ErrNotFound) {
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if err != nil {
		h.logger.Error("project detail", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	areaID := ""
	if p.AreaID != nil {
		areaID = p.AreaID.String()
	}

	resp := map[string]any{
		"id":              p.ID.String(),
		"title":           p.Title,
		"slug":            p.Slug,
		"description":     p.Description,
		"status":          string(p.Status),
		"area":            areaID,
		"problem":         stringOrEmpty(p.Problem),
		"solution":        stringOrEmpty(p.Solution),
		"architecture":    stringOrEmpty(p.Architecture),
		"recent_activity": []any{},
		"related_content": []any{},
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

	api.Encode(w, http.StatusOK, resp)
}
