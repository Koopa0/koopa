package task

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
	"github.com/koopa0/blog-backend/internal/notion"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
}

// Handler handles task HTTP requests.
type Handler struct {
	store    *Store
	notion   *notion.Client
	notionDB *notion.Store
	projects HTTPProjectResolver
	logger   *slog.Logger
}

// HTTPProjectResolver resolves a project identifier to (project_id, project_title).
// Returns an error if the project is not found.
type HTTPProjectResolver func(ctx context.Context, slug string) (uuid.UUID, string, error)

// HandlerOption configures optional Handler dependencies.
type HandlerOption func(*Handler)

// WithNotion enables Notion integration for task creation and completion.
func WithNotion(client *notion.Client, store *notion.Store) HandlerOption {
	return func(h *Handler) {
		h.notion = client
		h.notionDB = store
	}
}

// WithHTTPProjectResolver enables project slug resolution for task creation/update.
func WithHTTPProjectResolver(p HTTPProjectResolver) HandlerOption {
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

	if h.notion == nil || h.notionDB == nil {
		api.Error(w, http.StatusServiceUnavailable, "NOT_CONFIGURED", "notion integration not configured")
		return
	}

	src, err := h.notionDB.SourceByRole(ctx, "tasks")
	if err != nil {
		h.logger.Error("resolving task database id", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to resolve task database")
		return
	}

	pageID, err := h.notion.CreateTask(ctx, &notion.CreateTaskParams{
		DatabaseID:  src.DatabaseID,
		Title:       req.Title,
		DueDate:     req.Due,
		Description: req.Notes,
	})
	if err != nil {
		h.logger.Error("creating notion task", "error", err)
		api.Error(w, http.StatusInternalServerError, "NOTION_ERROR", "failed to create task in Notion")
		return
	}

	due, parseErr := parseDueDate(req.Due)
	if parseErr != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_DATE", "due must be YYYY-MM-DD")
		return
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
		Assignee:     "human",
	})
	if upsertErr != nil {
		h.logger.Error("local upsert after notion create", "error", upsertErr)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "task created in Notion but local save failed")
		return
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
	params, parseErr := h.buildUpdateParams(ctx, id, req)
	if parseErr != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_DATE", "due must be YYYY-MM-DD")
		return
	}

	// Sync to Notion before local update (best-effort)
	if t, taskErr := h.store.TaskByID(ctx, id); taskErr == nil && t.NotionPageID != nil {
		h.syncNotionProps(ctx, *t.NotionPageID, buildHTTPNotionProps(req))
	}

	updated, err := h.store.Update(ctx, params)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
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

// buildUpdateParams maps an HTTP update request into store-level UpdateParams.
// Returns an error only if due date parsing fails.
func (h *Handler) buildUpdateParams(ctx context.Context, id uuid.UUID, req updateRequest) (*UpdateParams, error) {
	params := &UpdateParams{ID: id}

	if req.Status != nil {
		st := mapHTTPTaskStatus(*req.Status)
		params.Status = &st
	}
	if req.Due != nil {
		d, parseErr := parseDueDate(*req.Due)
		if parseErr != nil {
			return nil, parseErr
		}
		params.Due = d
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
	return params, nil
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

	// notes reserved for future use; decode is best-effort
	_, _ = api.Decode[completeRequest](w, r)

	ctx := r.Context()

	t, err := h.store.TaskByID(ctx, id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	// Sync to Notion (best-effort)
	if t.NotionPageID != nil && h.notion != nil {
		if notionErr := h.notion.UpdatePageStatus(ctx, *t.NotionPageID, "Done"); notionErr != nil {
			h.logger.Warn("updating notion task status", "error", notionErr)
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
	myDayFalse := map[string]any{"My Day": map[string]any{"checkbox": false}}
	myDayTrue := map[string]any{"My Day": map[string]any{"checkbox": true}}
	var cleared int64

	if req.Clear {
		// Sync to Notion before clearing (best-effort)
		h.syncNotionClearMyDay(ctx, myDayFalse)

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

		// Sync to Notion (best-effort)
		if t, taskErr := h.store.TaskByID(ctx, id); taskErr == nil && t.NotionPageID != nil {
			h.syncNotionProps(ctx, *t.NotionPageID, myDayTrue)
		}
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

// parseDueDate parses a YYYY-MM-DD string into a *time.Time.
// Returns nil, nil for an empty string.
func parseDueDate(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// syncNotionProps updates a Notion page's properties as a best-effort operation.
// Errors are logged but not returned; callers should proceed regardless.
func (h *Handler) syncNotionProps(ctx context.Context, pageID string, props map[string]any) {
	if h.notion == nil || len(props) == 0 {
		return
	}
	if err := h.notion.UpdatePageProperties(ctx, pageID, props); err != nil {
		h.logger.Warn("notion sync failed", "page_id", pageID, "error", err)
	}
}

// syncNotionClearMyDay syncs all current My Day tasks to Notion before clearing (best-effort).
func (h *Handler) syncNotionClearMyDay(ctx context.Context, props map[string]any) {
	if h.notion == nil {
		return
	}
	tasks, err := h.store.MyDayTasksWithNotionPageID(ctx)
	if err != nil {
		h.logger.Warn("batch my day: fetching notion ids for clear", "error", err)
		return
	}
	for _, t := range tasks {
		//nolint:errcheck // best-effort
		h.notion.UpdatePageProperties(ctx, t.NotionPageID, props)
	}
}

// buildHTTPNotionProps builds Notion properties from an HTTP update request.
func buildHTTPNotionProps(req updateRequest) map[string]any {
	props := make(map[string]any)
	if req.Status != nil {
		notionStatus := "To Do"
		switch *req.Status {
		case "todo", "To Do":
			notionStatus = "To Do"
		case "in-progress", "Doing":
			notionStatus = "Doing"
		case "done", "Done":
			notionStatus = "Done"
		}
		props["Status"] = map[string]any{"status": map[string]string{"name": notionStatus}}
	}
	if req.Due != nil {
		if *req.Due == "" {
			props["Due"] = map[string]any{"date": nil}
		} else {
			props["Due"] = map[string]any{"date": map[string]string{"start": *req.Due}}
		}
	}
	if req.Priority != nil {
		props["Priority"] = map[string]any{"status": map[string]string{"name": *req.Priority}}
	}
	if req.Energy != nil {
		props["Energy"] = map[string]any{"select": map[string]string{"name": *req.Energy}}
	}
	if req.MyDay != nil {
		props["My Day"] = map[string]any{"checkbox": *req.MyDay}
	}
	return props
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
