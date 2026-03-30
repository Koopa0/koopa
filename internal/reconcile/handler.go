package reconcile

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Koopa0/koopa0.dev/internal/api"
)

// Handler handles reconcile history HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a reconcile Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// History handles GET /api/admin/reconcile/history.
func (h *Handler) History(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 100 {
		limit = 20
	}

	runs, err := h.store.RecentRuns(r.Context(), limit)
	if err != nil {
		h.logger.Error("listing reconcile runs", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list reconcile runs")
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: runs})
}
