package flow

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
	"github.com/koopa0/blog-backend/internal/content"
)

// ErrNotFound indicates a flow-related resource was not found.
// Defined separately from flowrun.ErrNotFound to break the flow ↔ flowrun import cycle.
// The runReader bridge in cmd/app/main.go translates between the two.
var ErrNotFound = errors.New("not found")

// RunResult holds the fields the handler needs from a flow run,
// avoiding a direct import of the flowrun package (which imports flow).
type RunResult struct {
	ID        uuid.UUID
	FlowName  string
	ContentID *uuid.UUID
	Status    string
	Output    json.RawMessage
	EndedAt   *time.Time
}

// Status constants matching flowrun.Status values.
// Duplicated here to avoid importing flowrun (import cycle).
const statusCompleted = "completed"

// JobSubmitter submits a flow run for async processing.
type JobSubmitter interface {
	Submit(ctx context.Context, flowName string, input json.RawMessage, contentID *uuid.UUID) error
}

// RunReader reads flow run results.
type RunReader interface {
	RunResult(ctx context.Context, id uuid.UUID) (*RunResult, error)
	LatestCompletedRunResult(ctx context.Context, flowName string, contentID uuid.UUID) (*RunResult, error)
}

// Handler handles flow admin HTTP requests (trigger, result, approve).
type Handler struct {
	jobs    JobSubmitter
	runs    RunReader
	content ContentReader
	updater ContentUpdater
	logger  *slog.Logger
}

// NewHandler returns a flow Handler.
func NewHandler(jobs JobSubmitter, runs RunReader, checker ContentReader, updater ContentUpdater, logger *slog.Logger) *Handler {
	return &Handler{
		jobs:    jobs,
		runs:    runs,
		content: checker,
		updater: updater,
		logger:  logger,
	}
}

// TriggerPolish handles POST /api/admin/flow/polish/{content_id}.
func (h *Handler) TriggerPolish(w http.ResponseWriter, r *http.Request) {
	contentID, err := uuid.Parse(r.PathValue("content_id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content ID")
		return
	}

	// verify content exists
	if _, err := h.content.Content(r.Context(), contentID); err != nil {
		if errors.Is(err, content.ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "content not found")
			return
		}
		h.logger.Error("checking content", "content_id", contentID, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to check content")
		return
	}

	input, err := json.Marshal(ContentPolishInput{ContentID: contentID.String()})
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

	run, err := h.runs.LatestCompletedRunResult(r.Context(), "content-polish", contentID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "no completed polish run found")
			return
		}
		h.logger.Error("querying polish result", "content_id", contentID, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query polish result")
		return
	}

	var output ContentPolishOutput
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

// approveRequest is the request body for ApprovePolish.
type approveRequest struct {
	RunID string `json:"run_id"`
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	runID, err := uuid.Parse(req.RunID)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid run ID")
		return
	}

	// fetch the run and verify it's a completed content-polish run
	run, err := h.runs.RunResult(r.Context(), runID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "flow run not found")
			return
		}
		h.logger.Error("querying flow run", "run_id", runID, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query flow run")
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
	if run.Status != statusCompleted {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "run is not completed")
		return
	}

	var output ContentPolishOutput
	if err := json.Unmarshal(run.Output, &output); err != nil {
		h.logger.Error("unmarshaling polish output", "run_id", runID, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to parse polish output")
		return
	}

	// apply polished body to content
	updated, err := h.updater.UpdateContent(r.Context(), contentID, content.UpdateParams{
		Body: &output.PolishedBody,
	})
	if err != nil {
		if errors.Is(err, content.ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "content not found")
			return
		}
		h.logger.Error("applying polish result", "content_id", contentID, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to apply polish result")
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: updated})
}
