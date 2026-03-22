package goal

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"

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

// updateStatusRequest is the JSON body for PUT /api/admin/goals/{id}/status.
type updateStatusRequest struct {
	Status string `json:"status"`
}

// UpdateStatus handles PUT /api/admin/goals/{id}/status — updates goal status.
func (h *Handler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_ID", "invalid goal id")
		return
	}

	req, err := api.Decode[updateStatusRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if req.Status == "" {
		api.Error(w, http.StatusBadRequest, "MISSING_STATUS", "status is required")
		return
	}

	status := mapHTTPGoalStatus(req.Status)

	updated, err := h.store.UpdateStatus(r.Context(), id, status)
	if err != nil {
		h.logger.Error("updating goal status", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to update goal status")
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: map[string]any{
		"title":      updated.Title,
		"status":     string(updated.Status),
		"area":       updated.Area,
		"updated_at": updated.UpdatedAt,
	}})
}

func mapHTTPGoalStatus(s string) Status {
	switch s {
	case "not-started", "Not Started", "Dream":
		return StatusNotStarted
	case "in-progress", "In Progress", "Active":
		return StatusInProgress
	case "done", "Done", "Achieved":
		return StatusDone
	case "abandoned", "Abandoned":
		return StatusAbandoned
	default:
		return StatusNotStarted
	}
}
