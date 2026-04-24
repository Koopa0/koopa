package project

import (
	"context"
	"errors"
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

// PublicList handles GET /api/projects — returns only public projects.
func (h *Handler) PublicList(w http.ResponseWriter, r *http.Request) {
	projects, err := h.store.PublicProjects(r.Context())
	if err != nil {
		h.logger.Error("listing public projects", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list projects")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: projects})
}

// Detail handles GET /api/admin/projects/{id} — returns the admin-facing
// aggregate (project + profile + goal breadcrumb + tasks grouped by state
// + recent activity + related content). Assembled from the core project
// row plus reader dependencies. Missing cross-feature data (e.g. profile
// absent because no case study yet, goal deleted) renders as nil or
// empty slices rather than 404'ing the detail response.
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
	h.loadDetailProfile(ctx, id, &detail)
	h.loadDetailTasks(ctx, id, &detail)
	h.loadDetailActivity(ctx, proj.Slug, &detail)
	h.loadDetailContent(ctx, id, &detail)

	api.Encode(w, http.StatusOK, api.Response{Data: detail})
}

// loadDetailProfile fills profile-sourced case-study fields. Missing
// profile is normal — a project may exist before a case study is written.
func (h *Handler) loadDetailProfile(ctx context.Context, id uuid.UUID, detail *Detail) {
	profile, err := h.store.ProfileByProjectID(ctx, id)
	if err == nil {
		detail.Problem = profile.Problem
		detail.Solution = profile.Solution
		detail.Architecture = profile.Architecture
		return
	}
	if !errors.Is(err, ErrNotFound) {
		h.logger.Warn("project detail: profile lookup failed", "project_id", id, "error", err)
	}
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

// BySlug handles GET /api/projects/{slug}.
func (h *Handler) BySlug(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	p, err := h.store.ProjectBySlug(r.Context(), slug)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: p})
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

// PublicPortfolio handles GET /api/portfolio — returns all public project profiles.
func (h *Handler) PublicPortfolio(w http.ResponseWriter, r *http.Request) {
	listings, err := h.store.PublicProfiles(r.Context())
	if err != nil {
		h.logger.Error("listing public profiles", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list portfolio")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: listings})
}

// GetProfile handles GET /api/admin/projects/{id}/profile.
func (h *Handler) GetProfile(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid project id")
		return
	}
	profile, err := h.store.ProfileByProjectID(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: profile})
}

// profileBody is the request body for PUT /api/admin/projects/{id}/profile.
// project_id comes from the path parameter, not the body.
type profileBody struct {
	LongDescription *string  `json:"long_description,omitempty"`
	Role            *string  `json:"role,omitempty"`
	TechStack       []string `json:"tech_stack"`
	Highlights      []string `json:"highlights"`
	Problem         *string  `json:"problem,omitempty"`
	Solution        *string  `json:"solution,omitempty"`
	Architecture    *string  `json:"architecture,omitempty"`
	Results         *string  `json:"results,omitempty"`
	GithubURL       *string  `json:"github_url,omitempty"`
	LiveURL         *string  `json:"live_url,omitempty"`
	CoverImage      *string  `json:"cover_image,omitempty"`
	Featured        bool     `json:"featured"`
	IsPublic        bool     `json:"is_public"`
	SortOrder       int      `json:"sort_order"`
}

// UpsertProfile handles PUT /api/admin/projects/{id}/profile.
func (h *Handler) UpsertProfile(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid project id")
		return
	}
	body, err := api.Decode[profileBody](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	profile, err := store.UpsertProfile(r.Context(), &UpsertProfileParams{
		ProjectID:       id,
		LongDescription: body.LongDescription,
		Role:            body.Role,
		TechStack:       body.TechStack,
		Highlights:      body.Highlights,
		Problem:         body.Problem,
		Solution:        body.Solution,
		Architecture:    body.Architecture,
		Results:         body.Results,
		GithubURL:       body.GithubURL,
		LiveURL:         body.LiveURL,
		CoverImage:      body.CoverImage,
		Featured:        body.Featured,
		IsPublic:        body.IsPublic,
		SortOrder:       body.SortOrder,
	})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: profile})
}

// DeleteProfile handles DELETE /api/admin/projects/{id}/profile.
func (h *Handler) DeleteProfile(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid project id")
		return
	}
	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	if err := store.DeleteProfile(r.Context(), id); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
