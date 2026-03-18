package notion

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// SourceHandler handles admin HTTP requests for notion source CRUD.
type SourceHandler struct {
	store  *Store
	logger *slog.Logger
}

// NewSourceHandler returns a SourceHandler.
func NewSourceHandler(store *Store, logger *slog.Logger) *SourceHandler {
	return &SourceHandler{store: store, logger: logger}
}

// List handles GET /api/admin/notion-sources.
func (h *SourceHandler) List(w http.ResponseWriter, r *http.Request) {
	sources, err := h.store.Sources(r.Context())
	if err != nil {
		h.logger.Error("listing notion sources", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list notion sources")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: sources})
}

// ByID handles GET /api/admin/notion-sources/{id}.
func (h *SourceHandler) ByID(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid source id")
		return
	}

	src, err := h.store.Source(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "notion source not found")
		return
	}
	if err != nil {
		h.logger.Error("querying notion source", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to get notion source")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: src})
}

// Create handles POST /api/admin/notion-sources.
func (h *SourceHandler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateSourceParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.DatabaseID == "" || p.Name == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "database_id and name are required")
		return
	}
	if len(p.DatabaseID) > 255 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "database_id exceeds 255 characters")
		return
	}
	if len(p.Name) > 255 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "name exceeds 255 characters")
		return
	}
	if p.SyncMode == "" {
		p.SyncMode = SyncModeFull
	}
	if !ValidSyncMode(p.SyncMode) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid sync_mode, must be 'full' or 'events'")
		return
	}
	if p.PollInterval == "" {
		p.PollInterval = "15 minutes"
	}
	if !ValidPollInterval(p.PollInterval) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid poll_interval")
		return
	}
	if p.PropertyMap == nil {
		p.PropertyMap = []byte("{}")
	}
	if len(p.PropertyMap) > 64*1024 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "property_map exceeds 64 KB")
		return
	}
	if !json.Valid(p.PropertyMap) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "property_map is not valid JSON")
		return
	}

	src, err := h.store.CreateSource(r.Context(), p)
	if errors.Is(err, ErrConflict) {
		api.Error(w, http.StatusConflict, "CONFLICT", "database_id already registered")
		return
	}
	if err != nil {
		h.logger.Error("creating notion source", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to create notion source")
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: src})
}

// Update handles PUT /api/admin/notion-sources/{id}.
func (h *SourceHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid source id")
		return
	}

	p, err := api.Decode[UpdateSourceParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.SyncMode != nil && !ValidSyncMode(*p.SyncMode) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid sync_mode, must be 'full' or 'events'")
		return
	}
	if p.Name != nil && *p.Name == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "name cannot be empty")
		return
	}
	if p.Name != nil && len(*p.Name) > 255 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "name exceeds 255 characters")
		return
	}
	if p.PollInterval != nil && !ValidPollInterval(*p.PollInterval) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid poll_interval")
		return
	}
	if p.PropertyMap != nil && len(*p.PropertyMap) > 64*1024 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "property_map exceeds 64 KB")
		return
	}
	if p.PropertyMap != nil && !json.Valid(*p.PropertyMap) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "property_map is not valid JSON")
		return
	}

	src, err := h.store.UpdateSource(r.Context(), id, p)
	if errors.Is(err, ErrNotFound) {
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "notion source not found")
		return
	}
	if err != nil {
		h.logger.Error("updating notion source", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to update notion source")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: src})
}

// Delete handles DELETE /api/admin/notion-sources/{id}.
func (h *SourceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid source id")
		return
	}

	if err := h.store.DeleteSource(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "notion source not found")
			return
		}
		h.logger.Error("deleting notion source", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete notion source")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Toggle handles POST /api/admin/notion-sources/{id}/toggle.
func (h *SourceHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid source id")
		return
	}

	src, err := h.store.ToggleEnabled(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "notion source not found")
		return
	}
	if err != nil {
		h.logger.Error("toggling notion source", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to toggle notion source")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: src})
}
