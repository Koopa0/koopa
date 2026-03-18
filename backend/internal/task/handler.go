package task

import (
	"log/slog"
	"net/http"

	"github.com/koopa0/blog-backend/internal/api"
)

// Handler handles task HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a task Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
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
