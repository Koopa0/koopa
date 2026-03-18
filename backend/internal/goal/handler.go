package goal

import (
	"log/slog"
	"net/http"

	"github.com/koopa0/blog-backend/internal/api"
)

// Handler handles goal HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a goal Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// List handles GET /api/admin/goals — returns all goals.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	goals, err := h.store.Goals(r.Context())
	if err != nil {
		h.logger.Error("listing goals", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list goals")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: goals})
}
