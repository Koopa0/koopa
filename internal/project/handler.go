// Copyright 2026 Koopa. All rights reserved.

package project

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/activity"
	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/todo"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "project not found"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT", Message: "project conflict"},
	{Target: ErrInvalidInput, Status: http.StatusBadRequest, Code: "BAD_REQUEST", Message: "invalid project input"},
	{Target: ErrNotProposed, Status: http.StatusConflict, Code: "NOT_PROPOSED", Message: "project is not a proposed draft"},
}

// recentActivityLimit caps how many activity rows the detail endpoint
// surfaces. The inspector panel renders a short recency list; more than
// ~20 events would scroll beyond the fold and inflate the payload.
const recentActivityLimit = 20

// recentActivityWindow is how far back the detail endpoint scans for
// project activity. 90 days covers a typical "recent work" horizon
// without pulling project-lifetime history on every inspector open.
const recentActivityWindow = 90 * 24 * time.Hour

// Handler handles project HTTP requests.
type Handler struct {
	store    *Store
	todos    *todo.Store
	activity *activity.Store
	contents *content.Store
	logger   *slog.Logger
}

// NewHandler returns a project Handler wired with the cross-feature
// stores used by the admin detail endpoint. The goal breadcrumb is
// resolved at the SQL layer via ProjectDetailByID's LEFT JOIN — no goal
// store dependency is needed. Nil is acceptable for any reader — the
// detail handler renders empty collections for missing deps rather than
// failing.
func NewHandler(
	store *Store,
	todos *todo.Store,
	activityStore *activity.Store,
	contents *content.Store,
	logger *slog.Logger,
) *Handler {
	return &Handler{
		store:    store,
		todos:    todos,
		activity: activityStore,
		contents: contents,
		logger:   logger,
	}
}

// List handles GET /api/admin/projects — returns all projects.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	projects, err := h.store.Projects(r.Context())
	if err != nil {
		h.logger.Error("listing projects", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list projects")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: projects})
}

// Detail handles GET /api/admin/projects/{id} — returns the admin-facing
// aggregate (project + goal breadcrumb + tasks grouped by state + recent
// activity + related content). Assembled from the core project row plus
// reader dependencies. Missing cross-feature data (e.g. goal deleted)
// renders as nil or empty slices rather than 404'ing the detail response.
func (h *Handler) Detail(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid project id")
		return
	}

	ctx := r.Context()
	row, err := h.store.ProjectDetailByID(ctx, id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	proj := &row.Project

	detail := Detail{
		ID:             proj.ID,
		Title:          proj.Title,
		Slug:           proj.Slug,
		Description:    proj.Description,
		Status:         proj.Status,
		Area:           areaString(proj.AreaID),
		RecentActivity: []ActivityItem{},
		RelatedContent: []ContentSummary{},
	}
	if proj.GoalID != nil && row.GoalTitle != nil {
		detail.GoalBreadcrumb = &GoalBreadcrumb{
			GoalID:    *proj.GoalID,
			GoalTitle: *row.GoalTitle,
		}
	}
	h.loadDetailTasks(ctx, id, &detail)
	h.loadDetailActivity(ctx, proj.Slug, &detail)
	h.loadDetailContent(ctx, id, &detail)

	api.Encode(w, http.StatusOK, api.Response{Data: detail})
}

// loadDetailTasks fills TodosByState from the grouped todo store. The
// concrete shape (*todo.GroupedItems) already matches the frontend
// TodosByState contract after the GroupedItems reshape.
func (h *Handler) loadDetailTasks(ctx context.Context, id uuid.UUID, detail *Detail) {
	if h.todos == nil {
		return
	}
	grouped, err := h.todos.ItemsByProjectGrouped(ctx, id)
	if err != nil {
		h.logger.Warn("project detail: todo grouping failed", "project_id", id, "error", err)
		return
	}
	detail.TodosByState = grouped
}

// loadDetailActivity populates RecentActivity from project-scoped events
// within the recency window. The slug-based filter matches the existing
// EventsByFilters shape; conversion to ActivityItem insulates the wire
// contract from activity.Event evolution.
func (h *Handler) loadDetailActivity(ctx context.Context, slug string, detail *Detail) {
	if h.activity == nil {
		return
	}
	since := time.Now().Add(-recentActivityWindow)
	events, err := h.activity.EventsByFilters(ctx, since, time.Now(), nil, &slug, nil, recentActivityLimit)
	if err != nil {
		h.logger.Warn("project detail: activity lookup failed", "slug", slug, "error", err)
		return
	}
	detail.RecentActivity = activityItemsFromEvents(events)
}

// loadDetailContent populates RelatedContent from content-by-project
// briefs. Empty-list policy on error — the inspector renders the panel
// rather than blowing up on a side aggregate failing.
func (h *Handler) loadDetailContent(ctx context.Context, id uuid.UUID, detail *Detail) {
	if h.contents == nil {
		return
	}
	briefs, err := h.contents.BriefsByProjectID(ctx, id)
	if err != nil {
		h.logger.Warn("project detail: content lookup failed", "project_id", id, "error", err)
		return
	}
	detail.RelatedContent = contentSummariesFromBriefs(briefs)
}

// areaString renders a nullable area UUID as a plain string for the
// wire response. Kept inline because the only use is the detail
// endpoint and the inspector displays it verbatim.
func areaString(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// activityItemsFromEvents projects internal activity.Event rows to the
// wire ActivityItem shape the inspector renders. Title falls back to
// change_kind when the underlying row has no title (vcs push events
// carry a ref, not a title — Type/Timestamp are always sufficient for
// display). Returns an empty slice for nil/empty input so the JSON
// field encodes as [] not null.
func activityItemsFromEvents(events []activity.Event) []ActivityItem {
	items := make([]ActivityItem, 0, len(events))
	for i := range events {
		e := &events[i]
		title := e.ChangeKind
		if e.Title != nil && *e.Title != "" {
			title = *e.Title
		}
		items = append(items, ActivityItem{
			Type:      e.ChangeKind,
			Title:     title,
			Timestamp: e.Timestamp,
		})
	}
	return items
}

// contentSummariesFromBriefs projects content.Brief rows to the wire
// ContentSummary shape. Type is cast through a string so the wire
// contract stays independent of content.Type evolution.
func contentSummariesFromBriefs(briefs []content.Brief) []ContentSummary {
	out := make([]ContentSummary, 0, len(briefs))
	for i := range briefs {
		b := &briefs[i]
		out = append(out, ContentSummary{
			ID:    b.ID,
			Title: b.Title,
			Slug:  b.Slug,
			Type:  string(b.Type),
		})
	}
	return out
}

// Create handles POST /api/admin/projects.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Slug == "" || p.Title == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug and title are required")
		return
	}
	if p.Status == "" {
		p.Status = StatusInProgress
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	proj, err := store.CreateProject(r.Context(), &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: proj})
}

// Update handles PUT /api/admin/projects/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid project id")
		return
	}

	p, err := api.Decode[UpdateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if (p.Slug != nil && *p.Slug == "") || (p.Title != nil && *p.Title == "") {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug and title must not be empty")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	proj, err := store.UpdateProject(r.Context(), id, &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: proj})
}

// Delete handles DELETE /api/admin/projects/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid project id")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	if err := store.DeleteProject(r.Context(), id); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Proposals triage (activate / reject) ---
//
// Agents propose inert project drafts via MCP (propose_project); these admin
// handlers are where the single human owner acts on them. Activate flips
// proposed → in_progress; reject is a hard DELETE (linked todos/contents are
// SET NULL by their FKs). Both are behind adminMid, which binds the actor tx.
// The triage LIST/COUNT lives in the goal handler, which aggregates proposed
// goals + areas + projects into one response.

// ActivateProject handles POST /api/admin/commitment/projects/{id}/activate —
// proposed → in_progress. 404 when the project does not exist; 409 NOT_PROPOSED
// when it exists but is not a proposed draft.
func (h *Handler) ActivateProject(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid project id")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	p, err := store.ActivateProject(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: p})
}

// RejectProject handles DELETE /api/admin/commitment/projects/{id}/proposed —
// hard DELETE of a proposed project. 404 missing, 409 NOT_PROPOSED when the
// project is real. Returns 204 on success.
func (h *Handler) RejectProject(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid project id")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	if err := store.RejectProject(r.Context(), id); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
