package content

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/api"
)

// contentURL builds a URL from siteURL, content type, and slug,
// trimming trailing slashes to prevent double-slash in output.
func (h *Handler) contentURL(typ, slug string) string {
	base := strings.TrimRight(h.siteURL, "/")
	return fmt.Sprintf("%s/%s/%s", base, typ, slug)
}

// RSS handles GET /api/feed/rss.
func (h *Handler) RSS(w http.ResponseWriter, r *http.Request) {
	if data, ok := h.feedCache.Get("rss"); ok {
		w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
		_, _ = w.Write(data) // best-effort
		return
	}

	contents, err := h.store.PublishedForRSS(r.Context(), 20)
	if err != nil {
		h.logger.Error("generating rss", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
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
	for i := range contents {
		c := contents[i]
		pubDate := ""
		if c.PublishedAt != nil {
			pubDate = c.PublishedAt.Format(time.RFC1123Z)
		}
		items[i] = rssItem{
			Title:       c.Title,
			Link:        h.contentURL(string(c.Type), c.Slug),
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

	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(feed); err != nil {
		h.logger.Error("encoding rss", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	data := buf.Bytes()
	if !h.feedCache.SetWithTTL("rss", data, int64(len(data)), rssTTL) {
		h.logger.Warn("rss cache set rejected", "size", len(data))
	}

	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	_, _ = w.Write(data) // best-effort
}

// Sitemap handles GET /api/feed/sitemap.
func (h *Handler) Sitemap(w http.ResponseWriter, r *http.Request) {
	if data, ok := h.feedCache.Get("sitemap"); ok {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		_, _ = w.Write(data) // best-effort
		return
	}

	contents, err := h.store.AllPublishedSlugs(r.Context())
	if err != nil {
		h.logger.Error("generating sitemap", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
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
	for i := range contents {
		c := contents[i]
		urls[i] = sitemapURL{
			Loc:     h.contentURL(string(c.Type), c.Slug),
			LastMod: c.UpdatedAt.Format("2006-01-02"),
		}
	}

	sitemap := urlSet{
		XMLNS: "http://www.sitemaps.org/schemas/sitemap/0.9",
		URLs:  urls,
	}

	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(sitemap); err != nil {
		h.logger.Error("encoding sitemap", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	data := buf.Bytes()
	if !h.feedCache.SetWithTTL("sitemap", data, int64(len(data)), sitemapTTL) {
		h.logger.Warn("sitemap cache set rejected", "size", len(data))
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	_, _ = w.Write(data) // best-effort
}
