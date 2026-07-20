// Copyright 2026 Koopa. All rights reserved.

// public.go holds the unauthenticated HTTP handlers — the read-only
// surface served to end users via the Angular frontend. Admin handlers
// live in admin.go. The split is deliberate: a reader reviewing "what
// can anonymous traffic reach?" looks here and nowhere else.

package content

import (
	"net/http"
	"time"

	"github.com/Koopa0/koopa/internal/api"
)

// PublicList handles GET /api/contents.
func (h *Handler) PublicList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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
	w.Header().Set("Cache-Control", "no-store")
	slug := r.PathValue("slug")
	c, err := h.store.PublicContentBySlug(r.Context(), slug)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

// PublicByType handles GET /api/contents/by-type/{type}.
func (h *Handler) PublicByType(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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
