// Copyright 2026 Koopa. All rights reserved.

package topic

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/content"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "topic not found"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT", Message: "topic conflict"},
	{Target: ErrInvalidInput, Status: http.StatusBadRequest, Code: "BAD_REQUEST", Message: "invalid topic input"},
}

// Handler handles topic HTTP requests.
type Handler struct {
	store   *Store
	content ContentByTopicLister
	logger  *slog.Logger
}

// NewHandler returns a topic Handler.
func NewHandler(store *Store, contentReader ContentByTopicLister, logger *slog.Logger) *Handler {
	return &Handler{store: store, content: contentReader, logger: logger}
}

func (h *Handler) mustAdminTx(w http.ResponseWriter, r *http.Request) (*Store, bool) {
	tx, ok := api.TxFromContext(r.Context())
	if !ok {
		h.logger.Error("topic admin mutation without tx",
			"event", "middleware_not_wired",
			"method", r.Method, "path", r.URL.Path)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
		return nil, false
	}
	return h.store.WithTx(tx), true
}

// List handles GET /api/admin/knowledge/topics — every topic, including those
// with no published content, so the admin can manage and assign empty topics.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	topics, err := h.store.Topics(r.Context())
	if err != nil {
		h.logger.Error("listing topics", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list topics")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: topics})
}

// ListPublished handles GET /api/topics — only topics that carry at least one
// published piece, so the public index never surfaces an empty category.
func (h *Handler) ListPublished(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	all, err := h.store.Topics(r.Context())
	if err != nil {
		h.logger.Error("listing topics", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list topics")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: publishedOnly(all)})
}

// publishedOnly keeps the topics that carry at least one publicly visible
// published piece. The store's content_count counts only published content with
// is_public = true (the same predicate the public content listing uses), so a
// positive count means the topic has something live to show on the public index.
func publishedOnly(topics []Topic) []Topic {
	published := make([]Topic, 0, len(topics))
	for i := range topics {
		if topics[i].ContentCount > 0 {
			published = append(published, topics[i])
		}
	}
	return published
}

// topicWithContents is the response for GET /api/topics/{slug}.
type topicWithContents struct {
	Topic    *Topic            `json:"topic"`
	Contents []content.Content `json:"contents"`
}

// BySlug handles GET /api/topics/{slug}.
// Returns the topic and its published contents (paginated).
func (h *Handler) BySlug(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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

	api.Encode(w, http.StatusOK, api.PagedResponse(
		topicWithContents{Topic: t, Contents: contents},
		total, page, perPage,
	))
}

// Create handles POST /api/admin/knowledge/topics.
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

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	t, err := store.CreateTopic(r.Context(), &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: t})
}

// Update handles PUT /api/admin/knowledge/topics/{id}.
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
	if (p.Slug != nil && *p.Slug == "") || (p.Name != nil && *p.Name == "") {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug and name must not be empty")
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	t, err := store.UpdateTopic(r.Context(), id, &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: t})
}

// Delete handles DELETE /api/admin/knowledge/topics/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid topic id")
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	if err := store.DeleteTopic(r.Context(), id); err != nil {
		h.logger.Error("deleting topic", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete topic")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
