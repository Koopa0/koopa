package entry

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "collected item not found"},
}

// Handler handles collected data HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a collected data Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// List handles GET /api/admin/feed-entries.
// Query params: page, per_page, status, sort (default "" or "relevance").
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page, perPage := api.ParsePagination(r)
	f := Filter{Page: page, PerPage: perPage}
	if s := r.URL.Query().Get("status"); s != "" {
		f.Status = &s
	}
	if s := r.URL.Query().Get("sort"); s == "relevance" {
		f.Sort = s
	}

	data, total, err := h.store.Items(r.Context(), f)
	if err != nil {
		h.logger.Error("listing collected data", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list collected data")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(data, total, page, perPage))
}

// Curate handles POST /api/admin/feed-entries/{id}/curate.
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
	if req.ContentID == uuid.Nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "content_id is required")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	if err := store.Curate(r.Context(), id, req.ContentID); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Ignore handles POST /api/admin/feed-entries/{id}/ignore.
func (h *Handler) Ignore(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid id")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	if err := store.Ignore(r.Context(), id); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SubmitFeedback handles POST /api/admin/feed-entries/{id}/feedback.
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
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "feedback must be \"up\" or \"down\"")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	if err := store.UpdateFeedback(r.Context(), id, fb); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
