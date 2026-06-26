// Copyright 2026 Koopa. All rights reserved.

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

func (h *Handler) mustAdminTx(w http.ResponseWriter, r *http.Request) (*Store, bool) {
	tx, ok := api.TxFromContext(r.Context())
	if !ok {
		h.logger.Error("feed entry admin mutation without tx",
			"event", "middleware_not_wired",
			"method", r.Method, "path", r.URL.Path)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
		return nil, false
	}
	return h.store.WithTx(tx), true
}

// List handles GET /api/admin/feed-entries.
// Query params: page, per_page, status.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page, perPage := api.ParsePagination(r)
	f := Filter{Page: page, PerPage: perPage}
	if s := r.URL.Query().Get("status"); s != "" {
		f.Status = &s
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

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
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

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	if err := store.Ignore(r.Context(), id); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
