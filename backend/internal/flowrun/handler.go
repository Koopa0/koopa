package flowrun

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
}

// JobSubmitter submits a flow run for async processing.
type JobSubmitter interface {
	Submit(ctx context.Context, flowName string, input json.RawMessage, contentID *uuid.UUID) error
}

// Handler handles flow run admin HTTP requests.
type Handler struct {
	store  *Store
	jobs   JobSubmitter
	logger *slog.Logger
}

// NewHandler returns a flow run Handler.
func NewHandler(store *Store, jobs JobSubmitter, logger *slog.Logger) *Handler {
	return &Handler{store: store, jobs: jobs, logger: logger}
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
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: run})
}

// Retry handles POST /api/admin/flow-runs/{id}/retry.
func (h *Handler) Retry(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid flow run ID")
		return
	}

	run, err := h.store.Run(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	if run.Status != StatusFailed {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "only failed runs can be retried")
		return
	}

	if err := h.jobs.Submit(r.Context(), run.FlowName, run.Input, run.ContentID); err != nil {
		h.logger.Error("retrying flow run", "id", id, "flow_name", run.FlowName, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to submit retry")
		return
	}

	api.Encode(w, http.StatusAccepted, api.Response{Data: map[string]string{"status": "submitted"}})
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
