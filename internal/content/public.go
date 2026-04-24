// public.go holds the unauthenticated HTTP handlers — the read-only
// surface served to end users via the Angular frontend. Admin handlers
// live in admin.go. The split is deliberate: a reader reviewing "what
// can anonymous traffic reach?" looks here and nowhere else.

package content

import (
	"net/http"
	"strconv"
	"time"

	"github.com/Koopa0/koopa/internal/api"
)

const maxSlugLength = 200

// PublicList handles GET /api/contents.
func (h *Handler) PublicList(w http.ResponseWriter, r *http.Request) {
	f := h.parsePublicFilter(r)
	contents, total, err := h.store.PublicContents(r.Context(), f)
	if err != nil {
		h.logger.Error("listing contents", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list contents")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(contents, total, f.Page, f.PerPage))
}

// PublicBySlug handles GET /api/contents/{slug}.
func (h *Handler) PublicBySlug(w http.ResponseWriter, r *http.Request) {
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

// PublicByType handles GET /api/contents/by-type/{type}.
func (h *Handler) PublicByType(w http.ResponseWriter, r *http.Request) {
	t := Type(r.PathValue("type"))
	if !t.Valid() {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content type")
		return
	}
	f := h.parsePublicFilter(r)
	f.Type = &t
	contents, total, err := h.store.PublicContents(r.Context(), f)
	if err != nil {
		h.logger.Error("listing contents by type", "type", t, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list contents")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(contents, total, f.Page, f.PerPage))
}

// PublicSearch handles GET /api/search.
func (h *Handler) PublicSearch(w http.ResponseWriter, r *http.Request) {
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

// PublicRelated handles GET /api/contents/related/{slug}.
func (h *Handler) PublicRelated(w http.ResponseWriter, r *http.Request) {
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

func (h *Handler) parsePublicFilter(r *http.Request) PublicFilter {
	page, perPage := api.ParsePagination(r)
	f := PublicFilter{Page: page, PerPage: perPage}

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
