package project

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// Handler handles project HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a project Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// List handles GET /api/projects.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	projects, err := h.store.Projects(r.Context())
	if err != nil {
		h.logger.Error("listing projects", "error", err)
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
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "project not found")
			return
		}
		h.logger.Error("querying project", "slug", slug, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to get project")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: p})
}

// Create handles POST /api/admin/projects.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](r)
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

	proj, err := h.store.CreateProject(r.Context(), p)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			api.Error(w, http.StatusConflict, "CONFLICT", "project slug already exists")
			return
		}
		h.logger.Error("creating project", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to create project")
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

	p, err := api.Decode[UpdateParams](r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	proj, err := h.store.UpdateProject(r.Context(), id, p)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "project not found")
			return
		}
		if errors.Is(err, ErrConflict) {
			api.Error(w, http.StatusConflict, "CONFLICT", "project slug already exists")
			return
		}
		h.logger.Error("updating project", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to update project")
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
