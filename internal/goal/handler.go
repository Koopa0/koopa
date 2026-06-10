// Copyright 2026 Koopa. All rights reserved.

package goal

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/project"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "goal not found"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT", Message: "goal conflict"},
}

// Handler handles goal HTTP requests.
type Handler struct {
	store    *Store
	projects *project.Store
	logger   *slog.Logger
}

// NewHandler returns a goal Handler.
func NewHandler(store *Store, projects *project.Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, projects: projects, logger: logger}
}

// List handles GET /api/admin/goals — returns all goals, or only goals in
// the requested status when ?status= is supplied. The filtered path returns
// the richer ActiveGoalSummary shape (milestone counts + area name); the
// unfiltered path is unchanged.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	if raw := r.URL.Query().Get("status"); raw != "" {
		status, statusErr := mapHTTPGoalStatus(raw)
		if statusErr != nil {
			api.Error(w, http.StatusBadRequest, "INVALID_STATUS", statusErr.Error())
			return
		}
		canonical := string(status)
		summaries, err := h.store.GoalsByOptionalStatus(r.Context(), &canonical)
		if err != nil {
			h.logger.Error("listing goals by status", "status", canonical, "error", err)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list goals")
			return
		}
		api.Encode(w, http.StatusOK, api.Response{Data: summaries})
		return
	}

	goals, err := h.store.Goals(r.Context())
	if err != nil {
		h.logger.Error("listing goals", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list goals")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: goals})
}

// updateStatusRequest is the JSON body for PUT /api/admin/goals/{id}/status.
type updateStatusRequest struct {
	Status string `json:"status"`
}

// UpdateStatus handles PUT /api/admin/goals/{id}/status — updates goal status.
func (h *Handler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_ID", "invalid goal id")
		return
	}

	req, err := api.Decode[updateStatusRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if req.Status == "" {
		api.Error(w, http.StatusBadRequest, "MISSING_STATUS", "status is required")
		return
	}

	status, statusErr := mapHTTPGoalStatus(req.Status)
	if statusErr != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_STATUS", statusErr.Error())
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	updated, err := store.UpdateStatus(r.Context(), id, status)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: map[string]any{
		"title":      updated.Title,
		"status":     string(updated.Status),
		"area_id":    updated.AreaID,
		"updated_at": updated.UpdatedAt,
	}})
}

// goalDetailResponse is the full detail shape for GET /api/admin/goals/{id}.
type goalDetailResponse struct {
	ID          uuid.UUID       `json:"id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Status      Status          `json:"status"`
	AreaID      *uuid.UUID      `json:"area_id,omitempty"`
	AreaName    string          `json:"area_name,omitempty"`
	Deadline    *string         `json:"deadline,omitempty"`
	Quarter     *string         `json:"quarter,omitempty"`
	Milestones  []milestoneItem `json:"milestones"`
	Projects    []projectItem   `json:"projects"`
	Activity    []activityItem  `json:"recent_activity"`
	CreatedAt   string          `json:"created_at"`
	UpdatedAt   string          `json:"updated_at"`
}

type milestoneItem struct {
	ID             uuid.UUID `json:"id"`
	GoalID         uuid.UUID `json:"goal_id"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	TargetDeadline *string   `json:"target_deadline,omitempty"`
	CompletedAt    *string   `json:"completed_at,omitempty"`
	Position       int32     `json:"position"`
	CreatedAt      string    `json:"created_at"`
	UpdatedAt      string    `json:"updated_at"`
}

type projectItem struct {
	ID     uuid.UUID `json:"id"`
	Title  string    `json:"title"`
	Status string    `json:"status"`
}

type activityItem struct {
	Type      string  `json:"type"`
	Title     string  `json:"title"`
	RefID     string  `json:"ref_id"`
	RefSlug   *string `json:"ref_slug,omitempty"`
	Timestamp string  `json:"timestamp"`
}

// recentActivityLimit caps the number of activity items returned.
const recentActivityLimit = 20

// Detail handles GET /api/admin/goals/{id}.
func (h *Handler) Detail(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid goal id")
		return
	}

	g, err := h.store.ByID(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	milestones, err := h.store.MilestonesByGoal(r.Context(), id)
	if err != nil {
		h.logger.Error("listing milestones", "goal_id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list milestones")
		return
	}

	var projects []projectItem
	if h.projects != nil {
		var summaries []project.ProjectSummary
		summaries, err = h.projects.SummariesByGoalIDs(r.Context(), []uuid.UUID{id})
		if err != nil {
			h.logger.Error("listing projects for goal", "goal_id", id, "error", err)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list projects")
			return
		}
		projects = make([]projectItem, len(summaries))
		for i := range summaries {
			projects[i] = projectItem{
				ID:     summaries[i].ID,
				Title:  summaries[i].Title,
				Status: string(summaries[i].Status),
			}
		}
	}
	if projects == nil {
		projects = []projectItem{}
	}

	activity, err := h.store.RecentActivity(r.Context(), id, recentActivityLimit)
	if err != nil {
		h.logger.Error("listing goal activity", "goal_id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list activity")
		return
	}

	const isoFormat = "2006-01-02T15:04:05Z07:00"

	ms := make([]milestoneItem, len(milestones))
	for i := range milestones {
		m := &milestones[i]
		item := milestoneItem{
			ID:          m.ID,
			GoalID:      m.GoalID,
			Title:       m.Title,
			Description: m.Description,
			Position:    m.Position,
			CreatedAt:   m.CreatedAt.Format(isoFormat),
			UpdatedAt:   m.UpdatedAt.Format(isoFormat),
		}
		if m.TargetDeadline != nil {
			td := m.TargetDeadline.Format("2006-01-02")
			item.TargetDeadline = &td
		}
		if m.CompletedAt != nil {
			t := m.CompletedAt.Format(isoFormat)
			item.CompletedAt = &t
		}
		ms[i] = item
	}

	acts := make([]activityItem, len(activity))
	for i := range activity {
		a := &activity[i]
		acts[i] = activityItem{
			Type:      string(a.Type),
			Title:     a.Title,
			RefID:     a.RefID,
			RefSlug:   a.RefSlug,
			Timestamp: a.Timestamp.Format(isoFormat),
		}
	}

	var deadline *string
	if g.Deadline != nil {
		d := g.Deadline.Format("2006-01-02")
		deadline = &d
	}

	resp := goalDetailResponse{
		ID:          g.ID,
		Title:       g.Title,
		Description: g.Description,
		Status:      g.Status,
		AreaID:      g.AreaID,
		AreaName:    g.AreaName,
		Deadline:    deadline,
		Quarter:     g.Quarter,
		Milestones:  ms,
		Projects:    projects,
		Activity:    acts,
		CreatedAt:   g.CreatedAt.Format(isoFormat),
		UpdatedAt:   g.UpdatedAt.Format(isoFormat),
	}

	api.Encode(w, http.StatusOK, api.Response{Data: resp})
}

// createRequest is the JSON body for POST /api/admin/commitment/goals.
// Status is not accepted — the decision-stamp create always lands in
// status=not_started (the store enforces this); lifecycle transitions go
// through PUT /goals/{id}/status. area_id, deadline, and quarter are
// optional shaping fields.
type createRequest struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	AreaID      *uuid.UUID `json:"area_id,omitempty"`
	Deadline    *time.Time `json:"deadline,omitempty"`
	Quarter     *string    `json:"quarter,omitempty"`
}

// Create handles POST /api/admin/commitment/goals — the owner decision-stamp
// that replaces the removed propose_goal / commit MCP flow. The goal is
// created in status=not_started.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[createRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Title == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title is required")
		return
	}
	if containsControlChars(req.Title) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title must not contain control characters")
		return
	}
	if containsControlChars(req.Description) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "description must not contain control characters")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	g, err := store.Create(r.Context(), &CreateParams{
		Title:       req.Title,
		Description: req.Description,
		AreaID:      req.AreaID,
		Deadline:    req.Deadline,
		Quarter:     req.Quarter,
	})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: g})
}

// ListAreas handles GET /api/admin/commitment/areas — every PARA area,
// ordered by sort_order. Read-only; the admin UI uses it to populate the
// area selector when creating or updating a goal.
func (h *Handler) ListAreas(w http.ResponseWriter, r *http.Request) {
	areas, err := h.store.Areas(r.Context())
	if err != nil {
		h.logger.Error("listing areas", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list areas")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: areas})
}

// updateRequest is the JSON body for PUT /api/admin/commitment/goals/{id}.
// All fields are optional; omitted fields stay unchanged. Status is not
// accepted — lifecycle transitions go through PUT /goals/{id}/status.
type updateRequest struct {
	Title       *string    `json:"title,omitempty"`
	Description *string    `json:"description,omitempty"`
	Quarter     *string    `json:"quarter,omitempty"`
	Deadline    *time.Time `json:"deadline,omitempty"`
	AreaID      *uuid.UUID `json:"area_id,omitempty"`
}

// Update handles PUT /api/admin/commitment/goals/{id} — partial update of
// title / description / quarter / deadline / area_id. Returns the updated
// goal; 404 when the goal does not exist.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid goal id")
		return
	}
	req, err := api.Decode[updateRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Title != nil {
		if *req.Title == "" {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title must not be empty")
			return
		}
		if containsControlChars(*req.Title) {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title must not contain control characters")
			return
		}
	}
	if req.Description != nil && containsControlChars(*req.Description) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "description must not contain control characters")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	g, err := store.Update(r.Context(), &UpdateParams{
		ID:          id,
		Title:       req.Title,
		Description: req.Description,
		Quarter:     req.Quarter,
		Deadline:    req.Deadline,
		AreaID:      req.AreaID,
	})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: g})
}

// createMilestoneRequest is the JSON body for
// POST /api/admin/commitment/goals/{id}/milestones. goal_id comes from the
// path, not the body.
type createMilestoneRequest struct {
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	TargetDeadline *time.Time `json:"target_deadline,omitempty"`
}

// CreateMilestone handles POST /api/admin/commitment/goals/{id}/milestones —
// the owner decision-stamp that replaces the removed propose_milestone / commit
// MCP flow. goalID is the path parameter.
func (h *Handler) CreateMilestone(w http.ResponseWriter, r *http.Request) {
	goalID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid goal id")
		return
	}

	req, err := api.Decode[createMilestoneRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Title == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title is required")
		return
	}
	if containsControlChars(req.Title) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title must not contain control characters")
		return
	}
	if containsControlChars(req.Description) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "description must not contain control characters")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	m, err := store.CreateMilestone(r.Context(), goalID, req.Title, req.Description, req.TargetDeadline)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: m})
}

// updateMilestoneRequest is the JSON body for
// PUT /api/admin/commitment/goals/{id}/milestones/{mid}. All fields are
// optional; omitted fields stay unchanged.
type updateMilestoneRequest struct {
	Title          *string    `json:"title,omitempty"`
	Description    *string    `json:"description,omitempty"`
	TargetDeadline *time.Time `json:"target_deadline,omitempty"`
}

// UpdateMilestone handles PUT /api/admin/commitment/goals/{id}/milestones/{mid}
// — partial update of title / description / target_deadline. The milestone
// must belong to the goal in the path; a mismatch is a 404.
func (h *Handler) UpdateMilestone(w http.ResponseWriter, r *http.Request) {
	goalID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid goal id")
		return
	}
	mid, err := uuid.Parse(r.PathValue("mid"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid milestone id")
		return
	}
	req, err := api.Decode[updateMilestoneRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Title != nil {
		if *req.Title == "" {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title must not be empty")
			return
		}
		if containsControlChars(*req.Title) {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title must not contain control characters")
			return
		}
	}
	if req.Description != nil && containsControlChars(*req.Description) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "description must not contain control characters")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	m, err := store.UpdateMilestone(r.Context(), &UpdateMilestoneParams{
		ID:             mid,
		GoalID:         goalID,
		Title:          req.Title,
		Description:    req.Description,
		TargetDeadline: req.TargetDeadline,
	})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: m})
}

// DeleteMilestone handles DELETE /api/admin/commitment/goals/{id}/milestones/{mid}.
// The milestone must belong to the goal in the path; a mismatch is a 404.
// Completed milestones are deletable. Returns 204 on success.
func (h *Handler) DeleteMilestone(w http.ResponseWriter, r *http.Request) {
	goalID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid goal id")
		return
	}
	mid, err := uuid.Parse(r.PathValue("mid"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid milestone id")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	if err := store.DeleteMilestone(r.Context(), goalID, mid); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ToggleMilestone handles
// POST /api/admin/commitment/goals/{id}/milestones/{mid}/toggle — flips the
// milestone's completed_at (set to now if null, cleared if set). The goal id
// is in the path for routing/auditing symmetry; the toggle keys on the
// milestone id alone. Returns the updated milestone.
func (h *Handler) ToggleMilestone(w http.ResponseWriter, r *http.Request) {
	mid, err := uuid.Parse(r.PathValue("mid"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid milestone id")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	m, err := store.ToggleMilestone(r.Context(), mid)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: m})
}

func mapHTTPGoalStatus(s string) (Status, error) {
	switch s {
	case "not_started", "Not Started", "Dream":
		return StatusNotStarted, nil
	case "in_progress", "In Progress", "Active":
		return StatusInProgress, nil
	case "done", "Done", "Achieved":
		return StatusDone, nil
	case "abandoned", "Abandoned":
		return StatusAbandoned, nil
	case "on_hold", "On Hold", "Paused":
		return StatusOnHold, nil
	default:
		return "", fmt.Errorf("unknown goal status %q: valid values are not_started, in_progress, done, abandoned, on_hold", s)
	}
}
