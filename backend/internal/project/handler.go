package project

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT"},
}

// Handler handles project HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a project Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
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

	proj, err := h.store.CreateProject(r.Context(), &p)
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

	proj, err := h.store.UpdateProject(r.Context(), id, &p)
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

	if err := h.store.DeleteProject(r.Context(), id); err != nil {
		h.logger.Error("deleting project", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete project")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
