package stats

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Koopa0/koopa0.dev/internal/api"
)

// Handler handles admin stats HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a stats Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// Overview handles GET /api/admin/stats.
func (h *Handler) Overview(w http.ResponseWriter, r *http.Request) {
	overview, err := h.store.Overview(r.Context())
	if err != nil {
		h.logger.Error("querying admin stats", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query stats")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: overview})
}

// Drift handles GET /api/admin/stats/drift.
// Query params: days (default 30, max 90).
func (h *Handler) Drift(w http.ResponseWriter, r *http.Request) {
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 && d <= 90 {
			days = d
		}
	}

	report, err := h.store.Drift(r.Context(), days)
	if err != nil {
		h.logger.Error("querying drift report", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query drift")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: report})
}

// Learning handles GET /api/admin/stats/learning.
func (h *Handler) Learning(w http.ResponseWriter, r *http.Request) {
	dashboard, err := h.store.Learning(r.Context())
	if err != nil {
		h.logger.Error("querying learning dashboard", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query learning stats")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: dashboard})
}
