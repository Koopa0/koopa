package content

import (
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// Handler handles content HTTP requests.
type Handler struct {
	store   *Store
	siteURL string
	logger  *slog.Logger
}

// NewHandler returns a content Handler.
func NewHandler(store *Store, siteURL string, logger *slog.Logger) *Handler {
	return &Handler{store: store, siteURL: siteURL, logger: logger}
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
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "content not found")
			return
		}
		h.logger.Error("querying content", "slug", slug, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to get content")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

// ByType handles GET /api/contents/type/{type}.
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
	page, perPage := parsePagination(r)
	contents, total, err := h.store.Search(r.Context(), q, page, perPage)
	if err != nil {
		h.logger.Error("searching contents", "query", q, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to search")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(contents, total, page, perPage))
}

// RSS handles GET /api/feed/rss.
func (h *Handler) RSS(w http.ResponseWriter, r *http.Request) {
	contents, err := h.store.PublishedForRSS(r.Context(), 20)
	if err != nil {
		h.logger.Error("generating rss", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	type rssItem struct {
		XMLName     xml.Name `xml:"item"`
		Title       string   `xml:"title"`
		Link        string   `xml:"link"`
		Description string   `xml:"description"`
		PubDate     string   `xml:"pubDate"`
		GUID        string   `xml:"guid"`
	}

	type rssChannel struct {
		XMLName       xml.Name  `xml:"channel"`
		Title         string    `xml:"title"`
		Link          string    `xml:"link"`
		Description   string    `xml:"description"`
		LastBuildDate string    `xml:"lastBuildDate"`
		Items         []rssItem `xml:"item"`
	}

	type rss struct {
		XMLName xml.Name   `xml:"rss"`
		Version string     `xml:"version,attr"`
		Channel rssChannel `xml:"channel"`
	}

	items := make([]rssItem, len(contents))
	for i, c := range contents {
		pubDate := ""
		if c.PublishedAt != nil {
			pubDate = c.PublishedAt.Format(time.RFC1123Z)
		}
		items[i] = rssItem{
			Title:       c.Title,
			Link:        fmt.Sprintf("%s/%s/%s", h.siteURL, c.Type, c.Slug),
			Description: c.Excerpt,
			PubDate:     pubDate,
			GUID:        c.ID.String(),
		}
	}

	feed := rss{
		Version: "2.0",
		Channel: rssChannel{
			Title:         "koopa0.dev",
			Link:          h.siteURL,
			Description:   "Koopa's knowledge engine",
			LastBuildDate: time.Now().Format(time.RFC1123Z),
			Items:         items,
		},
	}

	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprint(w, xml.Header); err != nil {
		h.logger.Error("writing rss header", "error", err)
		return
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(feed); err != nil {
		h.logger.Error("encoding rss", "error", err)
	}
}

// Sitemap handles GET /api/feed/sitemap.
func (h *Handler) Sitemap(w http.ResponseWriter, r *http.Request) {
	contents, err := h.store.AllPublishedSlugs(r.Context())
	if err != nil {
		h.logger.Error("generating sitemap", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	type sitemapURL struct {
		XMLName xml.Name `xml:"url"`
		Loc     string   `xml:"loc"`
		LastMod string   `xml:"lastmod"`
	}

	type urlSet struct {
		XMLName xml.Name     `xml:"urlset"`
		XMLNS   string       `xml:"xmlns,attr"`
		URLs    []sitemapURL `xml:"url"`
	}

	urls := make([]sitemapURL, len(contents))
	for i, c := range contents {
		urls[i] = sitemapURL{
			Loc:     fmt.Sprintf("%s/%s/%s", h.siteURL, c.Type, c.Slug),
			LastMod: c.UpdatedAt.Format("2006-01-02"),
		}
	}

	sitemap := urlSet{
		XMLNS: "http://www.sitemaps.org/schemas/sitemap/0.9",
		URLs:  urls,
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprint(w, xml.Header); err != nil {
		h.logger.Error("writing sitemap header", "error", err)
		return
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(sitemap); err != nil {
		h.logger.Error("encoding sitemap", "error", err)
	}
}

// Create handles POST /api/admin/contents.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Slug == "" || p.Title == "" || p.Type == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug, title, and type are required")
		return
	}
	if p.Status == "" {
		p.Status = StatusDraft
	}
	if p.ReviewLevel == "" {
		p.ReviewLevel = ReviewStandard
	}
	if p.Tags == nil {
		p.Tags = []string{}
	}

	c, err := h.store.CreateContent(r.Context(), p)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			api.Error(w, http.StatusConflict, "CONFLICT", "content slug already exists")
			return
		}
		h.logger.Error("creating content", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to create content")
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

	p, err := api.Decode[UpdateParams](r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	c, err := h.store.UpdateContent(r.Context(), id, p)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "content not found")
			return
		}
		if errors.Is(err, ErrConflict) {
			api.Error(w, http.StatusConflict, "CONFLICT", "content slug already exists")
			return
		}
		h.logger.Error("updating content", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to update content")
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
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "content not found")
			return
		}
		h.logger.Error("publishing content", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to publish content")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

func (h *Handler) parseFilter(r *http.Request) Filter {
	page, perPage := parsePagination(r)
	f := Filter{Page: page, PerPage: perPage}

	if t := r.URL.Query().Get("type"); t != "" {
		ct := Type(t)
		f.Type = &ct
	}
	if tag := r.URL.Query().Get("tag"); tag != "" {
		f.Tag = &tag
	}
	return f
}

func parsePagination(r *http.Request) (page, perPage int) {
	page = 1
	perPage = 20

	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if pp := r.URL.Query().Get("per_page"); pp != "" {
		if v, err := strconv.Atoi(pp); err == nil && v > 0 && v <= 100 {
			perPage = v
		}
	}
	return page, perPage
}
