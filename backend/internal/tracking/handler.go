package tracking

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// Handler handles tracking topic HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a tracking Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// List handles GET /api/admin/tracking.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	topics, err := h.store.TrackingTopics(r.Context())
	if err != nil {
		h.logger.Error("listing tracking topics", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list tracking topics")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: topics})
}

// Create handles POST /api/admin/tracking.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Name == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "name is required")
		return
	}

	t, err := h.store.CreateTrackingTopic(r.Context(), p)
	if err != nil {
		h.logger.Error("creating tracking topic", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to create tracking topic")
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: t})
}

// Update handles PUT /api/admin/tracking/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid tracking topic id")
		return
	}

	p, err := api.Decode[UpdateParams](r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	t, err := h.store.UpdateTrackingTopic(r.Context(), id, p)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "tracking topic not found")
			return
		}
		h.logger.Error("updating tracking topic", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to update tracking topic")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: t})
}

// Delete handles DELETE /api/admin/tracking/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid tracking topic id")
		return
	}

	if err := h.store.DeleteTrackingTopic(r.Context(), id); err != nil {
		h.logger.Error("deleting tracking topic", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete tracking topic")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
