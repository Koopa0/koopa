package flowrun

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// Handler handles flow run admin HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a flow run Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// List handles GET /api/admin/flow-runs.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := h.parseFilter(r)
	runs, total, err := h.store.Runs(r.Context(), f)
	if err != nil {
		h.logger.Error("listing flow runs", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list flow runs")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(runs, total, f.Page, f.PerPage))
}

// ByID handles GET /api/admin/flow-runs/{id}.
func (h *Handler) ByID(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid flow run ID")
		return
	}

	run, err := h.store.Run(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "flow run not found")
			return
		}
		h.logger.Error("querying flow run", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query flow run")
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: run})
}

func (h *Handler) parseFilter(r *http.Request) Filter {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	f := Filter{Page: page, PerPage: perPage}

	if s := r.URL.Query().Get("status"); s != "" {
		switch Status(s) {
		case StatusPending, StatusRunning, StatusCompleted, StatusFailed:
			status := Status(s)
			f.Status = &status
		default:
			// ignore unknown status values
		}
	}

	return f
}
