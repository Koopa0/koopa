package topic

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
	"github.com/koopa0/blog-backend/internal/content"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT"},
}

// ContentReader reads published contents for a topic.
type ContentReader interface {
	ContentsByTopicID(ctx context.Context, topicID uuid.UUID, page, perPage int) ([]content.Content, int, error)
}

// topicsTTL is the cache duration for the full topics list.
const topicsTTL = 10 * time.Minute

// Handler handles topic HTTP requests.
type Handler struct {
	store      *Store
	content    ContentReader
	logger     *slog.Logger
	topicCache *ristretto.Cache[string, []Topic]
}

// NewHandler returns a topic Handler.
func NewHandler(store *Store, contentReader ContentReader, topicCache *ristretto.Cache[string, []Topic], logger *slog.Logger) *Handler {
	return &Handler{store: store, content: contentReader, topicCache: topicCache, logger: logger}
}

// List handles GET /api/topics.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	if topics, ok := h.topicCache.Get("topics"); ok {
		api.Encode(w, http.StatusOK, api.Response{Data: topics})
		return
	}

	topics, err := h.store.Topics(r.Context())
	if err != nil {
		h.logger.Error("listing topics", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list topics")
		return
	}

	h.topicCache.SetWithTTL("topics", topics, 1, topicsTTL)
	api.Encode(w, http.StatusOK, api.Response{Data: topics})
}

// topicWithContents is the response for GET /api/topics/{slug}.
type topicWithContents struct {
	Topic       *Topic            `json:"topic"`
	Contents    []content.Content `json:"contents"`
	RelatedTags []TagCount        `json:"related_tags"`
}

// BySlug handles GET /api/topics/{slug}.
// Returns the topic, its published contents (paginated), and top related tags.
func (h *Handler) BySlug(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	t, err := h.store.TopicBySlug(r.Context(), slug)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	page, perPage := api.ParsePagination(r)

	contents, total, err := h.content.ContentsByTopicID(r.Context(), t.ID, page, perPage)
	if err != nil {
		h.logger.Error("listing topic contents", "slug", slug, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list topic contents")
		return
	}

	tags, err := h.store.RelatedTags(r.Context(), t.ID, 15)
	if err != nil {
		h.logger.Error("listing related tags", "slug", slug, "error", err)
		tags = []TagCount{} // non-fatal: return empty tags, don't fail the request
	}

	api.Encode(w, http.StatusOK, api.PagedResponse(
		topicWithContents{Topic: t, Contents: contents, RelatedTags: tags},
		total, page, perPage,
	))
}

// Create handles POST /api/admin/topics.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Slug == "" || p.Name == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug and name are required")
		return
	}

	t, err := h.store.CreateTopic(r.Context(), &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	h.topicCache.Del("topics")
	api.Encode(w, http.StatusCreated, api.Response{Data: t})
}

// Update handles PUT /api/admin/topics/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid topic id")
		return
	}

	p, err := api.Decode[UpdateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	t, err := h.store.UpdateTopic(r.Context(), id, &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	h.topicCache.Del("topics")
	api.Encode(w, http.StatusOK, api.Response{Data: t})
}

// Delete handles DELETE /api/admin/topics/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid topic id")
		return
	}

	if err := h.store.DeleteTopic(r.Context(), id); err != nil {
		h.logger.Error("deleting topic", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete topic")
		return
	}
	h.topicCache.Del("topics")
	w.WriteHeader(http.StatusNoContent)
}
