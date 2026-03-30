package review

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

// Handler handles review queue HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a review Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// List handles GET /api/admin/review.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	reviews, err := h.store.PendingReviews(r.Context())
	if err != nil {
		h.logger.Error("listing reviews", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list reviews")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: reviews})
}

// Approve handles POST /api/admin/review/{id}/approve.
func (h *Handler) Approve(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid review id")
		return
	}

	if err := h.store.ApproveReview(r.Context(), id); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Reject handles POST /api/admin/review/{id}/reject.
func (h *Handler) Reject(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid review id")
		return
	}

	type rejectRequest struct {
		Notes string `json:"notes"`
	}
	req, err := api.Decode[rejectRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if req.Notes == "" {
		api.Error(w, http.StatusBadRequest, "MISSING_NOTES", "rejection notes are required")
		return
	}

	if err := h.store.RejectReview(r.Context(), id, req.Notes); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ApproveAfterEdit handles PUT /api/admin/review/{id}/edit — approves a review
// after the content has been edited externally. Validates the review exists before approving.
func (h *Handler) ApproveAfterEdit(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid review id")
		return
	}

	rev, err := h.store.Review(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	if err := h.store.ApproveReview(r.Context(), rev.ID); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
