package feed

import (
	"log/slog"
	"net/http"

	"context"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT"},
}

// ManualFetcher fetches new items from a feed on demand.
// Interface kept: prevents import cycle (feed → collector → feed).
type ManualFetcher interface {
	FetchFeed(ctx context.Context, f *Feed) ([]uuid.UUID, error)
}

// Handler handles feed HTTP requests.
type Handler struct {
	store   *Store
	fetcher ManualFetcher
	logger  *slog.Logger
}

// NewHandler returns a feed Handler.
func NewHandler(store *Store, fetcher ManualFetcher, logger *slog.Logger) *Handler {
	return &Handler{store: store, fetcher: fetcher, logger: logger}
}

// List handles GET /api/admin/feeds.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	var schedule *string
	if s := r.URL.Query().Get("schedule"); s != "" {
		schedule = &s
	}

	feeds, err := h.store.Feeds(r.Context(), schedule)
	if err != nil {
		h.logger.Error("listing feeds", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list feeds")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: feeds})
}

// Create handles POST /api/admin/feeds.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.URL == "" || p.Name == "" || p.Schedule == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "url, name, and schedule are required")
		return
	}
	if !ValidSchedule(p.Schedule) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid schedule value")
		return
	}

	f, err := h.store.CreateFeed(r.Context(), &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: f})
}

// Update handles PUT /api/admin/feeds/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid feed id")
		return
	}

	p, err := api.Decode[UpdateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Schedule != nil && !ValidSchedule(*p.Schedule) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid schedule value")
		return
	}

	f, err := h.store.UpdateFeed(r.Context(), id, &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: f})
}

// Delete handles DELETE /api/admin/feeds/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid feed id")
		return
	}

	if err := h.store.DeleteFeed(r.Context(), id); err != nil {
		h.logger.Error("deleting feed", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete feed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// fetchResponse is the response for POST /api/admin/feeds/{id}/fetch.
type fetchResponse struct {
	NewItems int `json:"new_items"`
}

// Fetch handles POST /api/admin/feeds/{id}/fetch.
func (h *Handler) Fetch(w http.ResponseWriter, r *http.Request) {
	if h.fetcher == nil {
		api.Error(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "feed fetcher not available")
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid feed id")
		return
	}

	f, err := h.store.Feed(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	ids, err := h.fetcher.FetchFeed(r.Context(), f)
	if err != nil {
		h.logger.Error("fetching feed", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to fetch feed")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: fetchResponse{NewItems: len(ids)}})
}
