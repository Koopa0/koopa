package feed

import (
	"log/slog"
	"net/http"

	"context"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
)

// maxTopicIDs caps the number of topic associations a single create or
// update request may carry. Kept intentionally small because feeds rarely
// span that many topics and the cap bounds the junction write size.
// Brief §9 C14 security posture.
const maxTopicIDs = 20

// storeErrors maps feed sentinel errors to HTTP responses.
//
// ErrTooManyTopicIDs and ErrInvalidTopicID originate in parseTopicIDs
// (not the store), but they share the 4xx mapping surface with store
// sentinels, so they live alongside them for consistency.
//
// ErrNotTransactional is deliberately absent from this list. It signals
// a server wiring bug (a mutation hit the store without WithTx) and the
// admin path should treat it as a 500 with server-side logging via
// HandleError's default fallthrough — surfacing the mistake in logs
// instead of quietly matching a 4xx code.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "feed not found"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT", Message: "feed conflict"},
	{Target: ErrTopicNotFound, Status: http.StatusBadRequest, Code: "TOPIC_NOT_FOUND", Message: "referenced topic not found"},
	{Target: ErrTooManyTopicIDs, Status: http.StatusBadRequest, Code: "BAD_REQUEST", Message: "too many topic_ids (max 20)"},
	{Target: ErrInvalidTopicID, Status: http.StatusBadRequest, Code: "BAD_REQUEST", Message: "invalid topic_id"},
}

// createRequest is the wire format for POST /api/admin/feeds. TopicIDs
// arrive as strings so the handler can reject malformed UUIDs with a 400
// before the store is touched, keeping the FK lookup off the hot error
// path.
type createRequest struct {
	URL      string       `json:"url"`
	Name     string       `json:"name"`
	Schedule string       `json:"schedule"`
	TopicIDs []string     `json:"topic_ids,omitempty"`
	Filter   FilterConfig `json:"filter_config"`
}

// updateRequest is the wire format for PUT /api/admin/feeds/{id}. The
// TopicIDs field follows three-state semantics that mirror the store:
// omitted (nil slice) leaves feed_topics untouched, [] clears it, and a
// populated list replaces it. Because encoding/json collapses an
// explicit `"topic_ids": null` to the same nil slice as an omitted key,
// callers that want to clear MUST send `[]` — this limitation is the
// price of keeping the type a plain []string instead of *[]string.
type updateRequest struct {
	URL      *string       `json:"url,omitempty"`
	Name     *string       `json:"name,omitempty"`
	Schedule *string       `json:"schedule,omitempty"`
	TopicIDs []string      `json:"topic_ids,omitempty"`
	Enabled  *bool         `json:"enabled,omitempty"`
	Filter   *FilterConfig `json:"filter_config,omitempty"`
}

// parseTopicIDs validates a slice of topic_id strings and returns their
// parsed UUID form. Errors surface as feature sentinels so the handler
// can funnel them through api.HandleError together with store sentinels.
//
// Return contract:
//   - (nil, nil)          — input was nil; store treats this as "no change"
//     on update and "no topics" on create.
//   - ([]uuid.UUID{}, nil) — input was a non-nil empty slice; store
//     clears the junction on update, no topics on create.
//   - (nil, ErrTooManyTopicIDs) — input exceeded the per-request cap.
//   - (nil, ErrInvalidTopicID)  — at least one entry failed UUID parse.
func parseTopicIDs(raw []string) ([]uuid.UUID, error) {
	if raw == nil {
		return nil, nil
	}
	if len(raw) > maxTopicIDs {
		return nil, ErrTooManyTopicIDs
	}
	out := make([]uuid.UUID, len(raw))
	for i, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, ErrInvalidTopicID
		}
		out[i] = id
	}
	return out, nil
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
	req, err := api.Decode[createRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.URL == "" || req.Name == "" || req.Schedule == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "url, name, and schedule are required")
		return
	}
	if !ValidSchedule(req.Schedule) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid schedule value")
		return
	}

	topicIDs, err := parseTopicIDs(req.TopicIDs)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	p := CreateParams{
		URL:      req.URL,
		Name:     req.Name,
		Schedule: req.Schedule,
		TopicIDs: topicIDs,
		Filter:   req.Filter,
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	f, err := store.CreateFeed(r.Context(), &p)
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

	req, err := api.Decode[updateRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Schedule != nil && !ValidSchedule(*req.Schedule) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid schedule value")
		return
	}

	// parseTopicIDs preserves the nil-vs-empty distinction: nil input
	// returns nil (leave junction untouched), and a non-nil [] input
	// returns a non-nil zero-length slice (clear the junction). The
	// store observes these two states literally.
	topicIDs, err := parseTopicIDs(req.TopicIDs)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	p := UpdateParams{
		URL:      req.URL,
		Name:     req.Name,
		Schedule: req.Schedule,
		TopicIDs: topicIDs,
		Enabled:  req.Enabled,
		Filter:   req.Filter,
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	f, err := store.UpdateFeed(r.Context(), id, &p)
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

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	if err := store.DeleteFeed(r.Context(), id); err != nil {
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
