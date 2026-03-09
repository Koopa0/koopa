package topic

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
	"github.com/koopa0/blog-backend/internal/content"
)

// ContentReader reads published contents for a topic.
type ContentReader interface {
	ContentsByTopicID(ctx context.Context, topicID uuid.UUID, page, perPage int) ([]content.Content, int, error)
}

// Handler handles topic HTTP requests.
type Handler struct {
	store   *Store
	content ContentReader
	logger  *slog.Logger
}

// NewHandler returns a topic Handler.
func NewHandler(store *Store, content ContentReader, logger *slog.Logger) *Handler {
	return &Handler{store: store, content: content, logger: logger}
}

// List handles GET /api/topics.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	topics, err := h.store.Topics(r.Context())
	if err != nil {
		h.logger.Error("listing topics", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list topics")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: topics})
}

// topicWithContents is the response for GET /api/topics/{slug}.
type topicWithContents struct {
	Topic    *Topic            `json:"topic"`
	Contents []content.Content `json:"contents"`
}

// BySlug handles GET /api/topics/{slug}.
// Returns the topic and its published contents (paginated).
func (h *Handler) BySlug(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	t, err := h.store.TopicBySlug(r.Context(), slug)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "topic not found")
			return
		}
		h.logger.Error("querying topic", "slug", slug, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to get topic")
		return
	}

	page, perPage := parsePagination(r)

	contents, total, err := h.content.ContentsByTopicID(r.Context(), t.ID, page, perPage)
	if err != nil {
		h.logger.Error("listing topic contents", "slug", slug, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list topic contents")
		return
	}

	api.Encode(w, http.StatusOK, api.PagedResponse(
		topicWithContents{Topic: t, Contents: contents},
		total, page, perPage,
	))
}

// Create handles POST /api/admin/topics.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Slug == "" || p.Name == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug and name are required")
		return
	}

	t, err := h.store.CreateTopic(r.Context(), p)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			api.Error(w, http.StatusConflict, "CONFLICT", "topic slug already exists")
			return
		}
		h.logger.Error("creating topic", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to create topic")
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: t})
}

// Update handles PUT /api/admin/topics/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid topic id")
		return
	}

	p, err := api.Decode[UpdateParams](r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	t, err := h.store.UpdateTopic(r.Context(), id, p)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "topic not found")
			return
		}
		if errors.Is(err, ErrConflict) {
			api.Error(w, http.StatusConflict, "CONFLICT", "topic slug already exists")
			return
		}
		h.logger.Error("updating topic", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to update topic")
		return
	}
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
	w.WriteHeader(http.StatusNoContent)
}

func parsePagination(r *http.Request) (page, perPage int) {
	page = 1
	perPage = 20
	if v := r.URL.Query().Get("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := r.URL.Query().Get("per_page"); v != "" {
		if pp, err := strconv.Atoi(v); err == nil && pp > 0 && pp <= 100 {
			perPage = pp
		}
	}
	return page, perPage
}
