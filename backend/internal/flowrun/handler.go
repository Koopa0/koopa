package flowrun

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/flow"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
	{Target: content.ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
}

// ContentReader reads content by ID.
type ContentReader interface {
	Content(ctx context.Context, id uuid.UUID) (*content.Content, error)
}

// ContentUpdater updates content fields.
type ContentUpdater interface {
	UpdateContent(ctx context.Context, id uuid.UUID, p *content.UpdateParams) (*content.Content, error)
}

// Handler handles flow run admin HTTP requests.
type Handler struct {
	store          *Store
	jobs           Submitter
	contentReader  ContentReader
	contentUpdater ContentUpdater
	logger         *slog.Logger
}

// NewHandler returns a flow run Handler.
func NewHandler(store *Store, jobs Submitter, logger *slog.Logger) *Handler {
	return &Handler{store: store, jobs: jobs, logger: logger}
}

// WithContentDeps sets optional content dependencies for polish endpoints.
func (h *Handler) WithContentDeps(reader ContentReader, updater ContentUpdater) {
	h.contentReader = reader
	h.contentUpdater = updater
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

// approveRequest is the request body for ApprovePolish.
type approveRequest struct {
	RunID string `json:"run_id"`
}

// TriggerPolish handles POST /api/admin/flow/polish/{content_id}.
func (h *Handler) TriggerPolish(w http.ResponseWriter, r *http.Request) {
	contentID, err := uuid.Parse(r.PathValue("content_id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content ID")
		return
	}

	// verify content exists
	if _, checkErr := h.contentReader.Content(r.Context(), contentID); checkErr != nil {
		api.HandleError(w, h.logger, checkErr, storeErrors...)
		return
	}

	input, err := json.Marshal(flow.ContentPolishInput{ContentID: contentID.String()})
	if err != nil {
		h.logger.Error("marshaling polish input", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to marshal input")
		return
	}

	if err := h.jobs.Submit(r.Context(), "content-polish", input, &contentID); err != nil {
		h.logger.Error("submitting content-polish", "content_id", contentID, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to submit polish job")
		return
	}

	api.Encode(w, http.StatusAccepted, api.Response{Data: map[string]string{"status": "submitted"}})
}

// PolishResult handles GET /api/admin/flow/polish/{content_id}/result.
func (h *Handler) PolishResult(w http.ResponseWriter, r *http.Request) {
	contentID, err := uuid.Parse(r.PathValue("content_id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content ID")
		return
	}

	run, err := h.store.LatestCompletedRun(r.Context(), "content-polish", contentID)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	var output flow.ContentPolishOutput
	if err := json.Unmarshal(run.Output, &output); err != nil {
		h.logger.Error("unmarshaling polish output", "run_id", run.ID, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to parse polish output")
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: map[string]any{
		"run_id":        run.ID,
		"original_body": output.OriginalBody,
		"polished_body": output.PolishedBody,
		"completed_at":  run.EndedAt,
	}})
}

// ApprovePolish handles POST /api/admin/flow/polish/{content_id}/approve.
func (h *Handler) ApprovePolish(w http.ResponseWriter, r *http.Request) {
	contentID, err := uuid.Parse(r.PathValue("content_id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content ID")
		return
	}

	var req approveRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	runID, err := uuid.Parse(req.RunID)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid run ID")
		return
	}

	// fetch the run and verify it's a completed content-polish run
	run, err := h.store.Run(r.Context(), runID)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	if run.FlowName != "content-polish" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "run is not a content-polish flow")
		return
	}
	if run.ContentID == nil || *run.ContentID != contentID {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "run does not belong to this content")
		return
	}
	if run.Status != StatusCompleted {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "run is not completed")
		return
	}

	var output flow.ContentPolishOutput
	if unmarshalErr := json.Unmarshal(run.Output, &output); unmarshalErr != nil {
		h.logger.Error("unmarshaling polish output", "run_id", runID, "error", unmarshalErr)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to parse polish output")
		return
	}

	// apply polished body to content
	updated, err := h.contentUpdater.UpdateContent(r.Context(), contentID, &content.UpdateParams{
		Body: &output.PolishedBody,
	})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: updated})
}
