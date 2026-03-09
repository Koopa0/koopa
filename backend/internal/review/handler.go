package review

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

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
		h.logger.Error("approving review", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to approve review")
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
	req, err := api.Decode[rejectRequest](r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if err := h.store.RejectReview(r.Context(), id, req.Notes); err != nil {
		h.logger.Error("rejecting review", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to reject review")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Edit handles PUT /api/admin/review/{id}/edit.
func (h *Handler) Edit(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid review id")
		return
	}

	// Get the review to find the content ID
	rev, err := h.store.Review(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "review not found")
			return
		}
		h.logger.Error("querying review", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to get review")
		return
	}

	// Approve the review after edit
	if err := h.store.ApproveReview(r.Context(), rev.ID); err != nil {
		h.logger.Error("approving review after edit", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to approve review")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
