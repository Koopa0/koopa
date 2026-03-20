package collected

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// Handler handles collected data HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a collected data Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// List handles GET /api/admin/collected.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page := 1
	perPage := 20
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if pp := r.URL.Query().Get("per_page"); pp != "" {
		if v, err := strconv.Atoi(pp); err == nil && v > 0 && v <= 100 {
			perPage = v
		}
	}

	f := Filter{Page: page, PerPage: perPage}
	if s := r.URL.Query().Get("status"); s != "" {
		f.Status = &s
	}

	data, total, err := h.store.CollectedData(r.Context(), f)
	if err != nil {
		h.logger.Error("listing collected data", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list collected data")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(data, total, page, perPage))
}

// Curate handles POST /api/admin/collected/{id}/curate.
func (h *Handler) Curate(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid id")
		return
	}

	type curateRequest struct {
		ContentID uuid.UUID `json:"content_id"`
	}
	req, err := api.Decode[curateRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if err := h.store.Curate(r.Context(), id, req.ContentID); err != nil {
		h.logger.Error("curating collected data", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to curate")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Ignore handles POST /api/admin/collected/{id}/ignore.
func (h *Handler) Ignore(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid id")
		return
	}

	if err := h.store.Ignore(r.Context(), id); err != nil {
		h.logger.Error("ignoring collected data", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to ignore")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SubmitFeedback handles POST /api/admin/collected/{id}/feedback.
func (h *Handler) SubmitFeedback(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid id")
		return
	}

	type feedbackRequest struct {
		Feedback string `json:"feedback"`
	}
	req, err := api.Decode[feedbackRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	fb := Feedback(req.Feedback)
	if fb != FeedbackUp && fb != FeedbackDown {
		api.Error(w, http.StatusUnprocessableEntity, "BAD_REQUEST", "feedback must be \"up\" or \"down\"")
		return
	}

	if err := h.store.UpdateFeedback(r.Context(), id, fb); err != nil {
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "collected data not found")
			return
		}
		h.logger.Error("updating feedback", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to update feedback")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
