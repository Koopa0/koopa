package task

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// Handler handles task HTTP requests.
type Handler struct {
	store      *Store
	notion     NotionClient
	projects   ProjectResolver
	dbResolver DBIDResolver
	logger     *slog.Logger
}

// NotionClient creates and updates tasks in Notion.
type NotionClient interface {
	UpdatePageStatus(ctx context.Context, pageID, status string) error
	CreateTaskPage(ctx context.Context, databaseID, title, dueDate, description string) (string, error)
}

// ProjectResolver resolves a project identifier to (project_id, project_title).
// Returns an error if the project is not found.
type ProjectResolver func(ctx context.Context, slug string) (uuid.UUID, string, error)

// DBIDResolver resolves the Notion database ID for a given role.
type DBIDResolver interface {
	DatabaseIDByRole(ctx context.Context, role string) (string, error)
}

// HandlerOption configures optional Handler dependencies.
type HandlerOption func(*Handler)

// WithNotion enables Notion integration for task creation and completion.
func WithNotion(n NotionClient, r DBIDResolver) HandlerOption {
	return func(h *Handler) {
		h.notion = n
		h.dbResolver = r
	}
}

// WithProjectResolver enables project slug resolution for task creation/update.
func WithProjectResolver(p ProjectResolver) HandlerOption {
	return func(h *Handler) { h.projects = p }
}

// NewHandler returns a task Handler.
func NewHandler(store *Store, logger *slog.Logger, opts ...HandlerOption) *Handler {
	h := &Handler{store: store, logger: logger}
	for _, o := range opts {
		o(h)
	}
	return h
}

// List handles GET /api/admin/tasks — returns all tasks.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	tasks, err := h.store.Tasks(r.Context())
	if err != nil {
		h.logger.Error("listing tasks", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list tasks")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: tasks})
}

// Pending handles GET /api/admin/tasks/pending — returns non-done tasks.
func (h *Handler) Pending(w http.ResponseWriter, r *http.Request) {
	tasks, err := h.store.PendingTasks(r.Context())
	if err != nil {
		h.logger.Error("listing pending tasks", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list pending tasks")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: tasks})
}

// createRequest is the JSON body for POST /api/admin/tasks.
type createRequest struct {
	Title    string `json:"title"`
	Project  string `json:"project_slug,omitempty"`
	Due      string `json:"due,omitempty"`
	Priority string `json:"priority,omitempty"`
	Energy   string `json:"energy,omitempty"`
	MyDay    bool   `json:"my_day,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// Create handles POST /api/admin/tasks — creates a task via Notion then local DB.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[createRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if req.Title == "" {
		api.Error(w, http.StatusBadRequest, "MISSING_TITLE", "title is required")
		return
	}

	ctx := r.Context()

	if h.notion == nil || h.dbResolver == nil {
		api.Error(w, http.StatusServiceUnavailable, "NOT_CONFIGURED", "notion integration not configured")
		return
	}

	taskDBID, err := h.dbResolver.DatabaseIDByRole(ctx, "tasks")
	if err != nil {
		h.logger.Error("resolving task database id", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to resolve task database")
		return
	}

	pageID, err := h.notion.CreateTaskPage(ctx, taskDBID, req.Title, req.Due, req.Notes)
	if err != nil {
		h.logger.Error("creating notion task", "error", err)
		api.Error(w, http.StatusInternalServerError, "NOTION_ERROR", "failed to create task in Notion")
		return
	}

	var due *time.Time
	if req.Due != "" {
		d, parseErr := time.Parse(time.DateOnly, req.Due)
		if parseErr != nil {
			api.Error(w, http.StatusBadRequest, "INVALID_DATE", "due must be YYYY-MM-DD")
			return
		}
		due = &d
	}

	var projectID *uuid.UUID
	var projectTitle string
	if req.Project != "" && h.projects != nil {
		pid, title, projErr := h.projects(ctx, req.Project)
		if projErr == nil {
			projectID = &pid
			projectTitle = title
		}
	}

	localTask, upsertErr := h.store.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
		Title:        req.Title,
		Status:       StatusTodo,
		Due:          due,
		ProjectID:    projectID,
		NotionPageID: pageID,
		Energy:       req.Energy,
		Priority:     req.Priority,
		MyDay:        req.MyDay,
		Description:  req.Notes,
	})
	if upsertErr != nil {
		h.logger.Error("local upsert after notion create", "error", upsertErr)
	}

	out := map[string]any{
		"task_id":    pageID,
		"title":      req.Title,
		"created_at": time.Now().Format(time.RFC3339),
	}
	if localTask != nil {
		out["task_id"] = localTask.ID.String()
	}
	if req.Due != "" {
		out["due"] = req.Due
	}
	if projectTitle != "" {
		out["project"] = projectTitle
	}

	h.logger.Info("task created via http", "title", req.Title, "due", req.Due)
	api.Encode(w, http.StatusCreated, api.Response{Data: out})
}

// updateRequest is the JSON body for PUT /api/admin/tasks/{id}.
type updateRequest struct {
	Status   *string `json:"status,omitempty"`
	Due      *string `json:"due,omitempty"`
	Priority *string `json:"priority,omitempty"`
	Energy   *string `json:"energy,omitempty"`
	MyDay    *bool   `json:"my_day,omitempty"`
	Project  *string `json:"project_slug,omitempty"`
	Notes    *string `json:"notes,omitempty"`
}

// Update handles PUT /api/admin/tasks/{id} — updates task properties.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_ID", "invalid task id")
		return
	}

	req, err := api.Decode[updateRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}

	ctx := r.Context()
	params := &UpdateParams{ID: id}

	if req.Status != nil {
		st := mapHTTPTaskStatus(*req.Status)
		params.Status = &st
	}
	if req.Due != nil {
		due, parseErr := time.Parse(time.DateOnly, *req.Due)
		if parseErr != nil {
			api.Error(w, http.StatusBadRequest, "INVALID_DATE", "due must be YYYY-MM-DD")
			return
		}
		params.Due = &due
	}
	if req.Priority != nil {
		params.Priority = req.Priority
	}
	if req.Energy != nil {
		params.Energy = req.Energy
	}
	if req.MyDay != nil {
		params.MyDay = req.MyDay
	}
	if req.Notes != nil {
		params.Description = req.Notes
	}
	if req.Project != nil && h.projects != nil {
		pid, _, projErr := h.projects(ctx, *req.Project)
		if projErr == nil {
			params.ProjectID = &pid
		}
	}

	updated, err := h.store.Update(ctx, params)
	if err != nil {
		h.logger.Error("updating task", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to update task")
		return
	}

	out := map[string]any{
		"task_id":    updated.ID.String(),
		"title":      updated.Title,
		"status":     string(updated.Status),
		"updated_at": updated.UpdatedAt.Format(time.RFC3339),
	}
	if updated.Due != nil {
		out["due"] = updated.Due.Format(time.DateOnly)
	}

	api.Encode(w, http.StatusOK, api.Response{Data: out})
}

// completeRequest is the JSON body for POST /api/admin/tasks/{id}/complete.
type completeRequest struct {
	Notes string `json:"notes,omitempty"`
}

// Complete handles POST /api/admin/tasks/{id}/complete — marks task as done.
func (h *Handler) Complete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_ID", "invalid task id")
		return
	}

	req, _ := api.Decode[completeRequest](w, r)
	_ = req // notes reserved for future use

	ctx := r.Context()

	t, err := h.store.TaskByID(ctx, id)
	if err != nil {
		h.logger.Error("querying task for complete", "id", id, "error", err)
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "task not found")
		return
	}

	// Sync to Notion (best-effort)
	if t.NotionPageID != nil && h.notion != nil {
		if notionErr := h.notion.UpdatePageStatus(ctx, *t.NotionPageID, "Done"); notionErr != nil {
			h.logger.Error("updating notion task status", "error", notionErr)
		}
	}

	updated, err := h.store.UpdateStatus(ctx, t.ID, StatusDone)
	if err != nil {
		h.logger.Error("completing task", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to complete task")
		return
	}

	out := map[string]any{
		"task_id":      updated.ID.String(),
		"title":        updated.Title,
		"completed_at": time.Now().Format(time.RFC3339),
		"is_recurring": updated.IsRecurring(),
	}
	if nextDue := updated.NextDue(); nextDue != nil {
		out["next_recurrence"] = nextDue.Format(time.DateOnly)
	}

	h.logger.Info("task completed via http", "task_id", updated.ID, "title", updated.Title)
	api.Encode(w, http.StatusOK, api.Response{Data: out})
}

// batchMyDayRequest is the JSON body for POST /api/admin/tasks/batch-my-day.
type batchMyDayRequest struct {
	TaskIDs []string `json:"task_ids"`
	Clear   bool     `json:"clear,omitempty"`
}

// BatchMyDay handles POST /api/admin/tasks/batch-my-day — sets My Day for multiple tasks.
func (h *Handler) BatchMyDay(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[batchMyDayRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if len(req.TaskIDs) == 0 && !req.Clear {
		api.Error(w, http.StatusBadRequest, "MISSING_IDS", "task_ids required or set clear: true")
		return
	}

	ctx := r.Context()
	var cleared int64

	if req.Clear {
		cleared, err = h.store.ClearAllMyDay(ctx)
		if err != nil {
			h.logger.Error("clearing my day", "error", err)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to clear my day")
			return
		}
	}

	var set int
	for _, idStr := range req.TaskIDs {
		id, parseErr := uuid.Parse(idStr)
		if parseErr != nil {
			h.logger.Error("batch my day: invalid id", "id", idStr)
			continue
		}
		if updateErr := h.store.UpdateMyDay(ctx, id, true); updateErr != nil {
			h.logger.Error("batch my day: setting", "task_id", idStr, "error", updateErr)
			continue
		}
		set++
	}

	api.Encode(w, http.StatusOK, api.Response{Data: map[string]any{
		"cleared_count": cleared,
		"set_count":     set,
	}})
}

// DailySummary handles GET /api/admin/today/summary — returns task completion metrics.
func (h *Handler) DailySummary(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	dayEnd := dayStart.Add(24 * time.Hour)

	hint, err := h.store.DailySummaryHintForDate(r.Context(), dayStart, dayEnd)
	if err != nil {
		h.logger.Error("computing daily summary", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to compute daily summary")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: hint})
}

func mapHTTPTaskStatus(s string) Status {
	switch s {
	case "todo", "To Do":
		return StatusTodo
	case "in-progress", "Doing", "In Progress":
		return StatusInProgress
	case "done", "Done":
		return StatusDone
	default:
		return StatusTodo
	}
}
