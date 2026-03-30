package monitor

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
}

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
	topics, err := h.store.Topics(r.Context())
	if err != nil {
		h.logger.Error("listing tracking topics", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list tracking topics")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: topics})
}

// Create handles POST /api/admin/tracking.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Name == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "name is required")
		return
	}

	t, err := h.store.Create(r.Context(), &p)
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

	p, err := api.Decode[UpdateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	t, err := h.store.Update(r.Context(), id, &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
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

	if err := h.store.Delete(r.Context(), id); err != nil {
		h.logger.Error("deleting tracking topic", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete tracking topic")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
