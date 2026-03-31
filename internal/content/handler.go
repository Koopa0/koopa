package content

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"

	"github.com/Koopa0/koopa0.dev/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT"},
}

// Cache TTLs for pre-serialized feed responses and knowledge graph.
// These caches expire on TTL only — no active invalidation on content writes.
// This is intentional: content mutations are infrequent and eventual consistency is acceptable.
const (
	graphTTL   = 10 * time.Minute
	rssTTL     = 10 * time.Minute
	sitemapTTL = 30 * time.Minute
)

// Handler handles content HTTP requests.
type Handler struct {
	store   *Store
	siteURL string
	logger  *slog.Logger

	graphCache *ristretto.Cache[string, *KnowledgeGraph]
	graphSF    singleflight.Group
	feedCache  *ristretto.Cache[string, []byte]
}

// NewHandler returns a content Handler.
// Caches are created internally — they are implementation details of this handler.
func NewHandler(
	store *Store,
	siteURL string,
	logger *slog.Logger,
) *Handler {
	graphCache, _ := ristretto.NewCache(&ristretto.Config[string, *KnowledgeGraph]{
		NumCounters: 10, // 10x expected items (1 key: "graph")
		MaxCost:     1,  // count-based: 1 item max
		BufferItems: 64,
	})
	feedCache, _ := ristretto.NewCache(&ristretto.Config[string, []byte]{
		NumCounters: 100,     // 10x expected items (2 keys: "rss", "sitemap")
		MaxCost:     1 << 20, // 1 MB byte budget
		BufferItems: 64,
	})
	return &Handler{
		store:      store,
		siteURL:    siteURL,
		graphCache: graphCache,
		feedCache:  feedCache,
		logger:     logger,
	}
}

// List handles GET /api/contents.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := h.parseFilter(r)
	contents, total, err := h.store.Contents(r.Context(), f)
	if err != nil {
		h.logger.Error("listing contents", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list contents")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(contents, total, f.Page, f.PerPage))
}

// BySlug handles GET /api/contents/{slug}.
func (h *Handler) BySlug(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	c, err := h.store.ContentBySlug(r.Context(), slug)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	if !c.IsPublic {
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "not found")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

// ByType handles GET /api/contents/by-type/{type}.
func (h *Handler) ByType(w http.ResponseWriter, r *http.Request) {
	t := Type(r.PathValue("type"))
	if !t.Valid() {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content type")
		return
	}
	f := h.parseFilter(r)
	f.Type = &t
	contents, total, err := h.store.Contents(r.Context(), f)
	if err != nil {
		h.logger.Error("listing contents by type", "type", t, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list contents")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(contents, total, f.Page, f.PerPage))
}

// Search handles GET /api/search.
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "query parameter q is required")
		return
	}

	var ct *Type
	if t := r.URL.Query().Get("type"); t != "" {
		v := Type(t)
		if v.Valid() {
			ct = &v
		}
	}

	page, perPage := api.ParsePagination(r)
	contents, total, err := h.store.Search(r.Context(), q, ct, page, perPage)
	if err != nil {
		h.logger.Error("searching contents", "query", q, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to search")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(contents, total, page, perPage))
}

// Create handles POST /api/admin/contents.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Slug == "" || p.Title == "" || p.Type == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug, title, and type are required")
		return
	}
	if !p.Type.Valid() {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content type")
		return
	}
	if p.Status == "" {
		p.Status = StatusDraft
	}
	if p.ReviewLevel == "" {
		p.ReviewLevel = ReviewStandard
	}
	// IsPublic defaults to false (zero value for bool) — callers set explicitly if needed

	c, err := h.store.CreateContent(r.Context(), &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: c})
}

// Update handles PUT /api/admin/contents/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}

	p, err := api.Decode[UpdateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Type != nil && !p.Type.Valid() {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content type")
		return
	}
	// IsPublic is a bool pointer — no validation needed beyond JSON decode

	c, err := h.store.UpdateContent(r.Context(), id, &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

// Delete handles DELETE /api/admin/contents/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}

	if err := h.store.DeleteContent(r.Context(), id); err != nil {
		h.logger.Error("deleting content", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete content")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Publish handles POST /api/admin/contents/{id}/publish.
func (h *Handler) Publish(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}

	c, err := h.store.PublishContent(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

const maxSlugLength = 200

// Related handles GET /api/contents/related/{slug}.
func (h *Handler) Related(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if len(slug) > maxSlugLength {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid slug")
		return
	}

	limit := 5
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 20 {
			limit = v
		}
	}

	id, embedding, err := h.store.ContentEmbeddingBySlug(r.Context(), slug)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	if embedding == nil {
		api.Encode(w, http.StatusOK, api.Response{Data: []RelatedContent{}})
		return
	}

	related, err := h.store.SimilarContents(r.Context(), id, *embedding, limit)
	if err != nil {
		h.logger.Error("querying similar contents", "slug", slug, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to get related contents")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: related})
}

func (h *Handler) parseFilter(r *http.Request) Filter {
	page, perPage := api.ParsePagination(r)
	f := Filter{Page: page, PerPage: perPage}

	if t := r.URL.Query().Get("type"); t != "" {
		ct := Type(t)
		if ct.Valid() {
			f.Type = &ct
		}
	}
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.DateOnly, s); err == nil {
			f.Since = &t
		}
	}
	return f
}

// AdminList handles GET /api/admin/contents.
func (h *Handler) AdminList(w http.ResponseWriter, r *http.Request) {
	page, perPage := api.ParsePagination(r)
	f := AdminFilter{Page: page, PerPage: perPage}

	if t := r.URL.Query().Get("type"); t != "" {
		ct := Type(t)
		if ct.Valid() {
			f.Type = &ct
		}
	}
	if v := r.URL.Query().Get("is_public"); v != "" {
		switch v {
		case "true":
			isPublic := true
			f.IsPublic = &isPublic
		case "false":
			isPublic := false
			f.IsPublic = &isPublic
		default:
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "is_public must be true or false")
			return
		}
	}

	contents, total, err := h.store.AdminContents(r.Context(), f)
	if err != nil {
		h.logger.Error("admin listing contents", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list contents")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(contents, total, f.Page, f.PerPage))
}

// SetIsPublic handles PATCH /api/admin/contents/{id}/is-public.
func (h *Handler) SetIsPublic(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}

	type isPublicBody struct {
		IsPublic bool `json:"is_public"`
	}
	body, decErr := api.Decode[isPublicBody](w, r)
	if decErr != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	c, err := h.store.UpdateContent(r.Context(), id, &UpdateParams{IsPublic: &body.IsPublic})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}
