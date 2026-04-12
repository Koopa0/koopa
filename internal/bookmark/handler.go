package bookmark

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT"},
}

// Handler handles bookmark HTTP requests.
//
// The public surface exposes List and BySlug, mirroring
// content.Handler.List / content.Handler.BySlug. The admin surface adds
// AdminList, AdminGet, Create, and Delete. During M1/M2 the admin Create
// path is the only write path into bookmarks — manage_content.bookmark_rss
// still writes to contents until M3 cutover.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a bookmark Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// List handles GET /api/bookmarks.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := parseFilter(r)
	bookmarks, total, err := h.store.Bookmarks(r.Context(), f)
	if err != nil {
		h.logger.Error("listing bookmarks", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list bookmarks")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(bookmarks, total, f.Page, f.PerPage))
}

// BySlug handles GET /api/bookmarks/{slug}.
func (h *Handler) BySlug(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug is required")
		return
	}
	b, err := h.store.BookmarkBySlug(r.Context(), slug)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: b})
}

// AdminList handles GET /api/admin/bookmarks.
func (h *Handler) AdminList(w http.ResponseWriter, r *http.Request) {
	f := parseAdminFilter(r)
	bookmarks, total, err := h.store.AdminBookmarks(r.Context(), f)
	if err != nil {
		h.logger.Error("admin listing bookmarks", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list bookmarks")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(bookmarks, total, f.Page, f.PerPage))
}

// AdminGet handles GET /api/admin/bookmarks/{id}.
func (h *Handler) AdminGet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid bookmark id")
		return
	}
	b, err := h.store.Bookmark(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: b})
}

// CreateRequest is the admin Create payload. It is distinct from
// CreateParams because the handler computes url_hash and slug from
// caller input instead of trusting them.
type CreateRequest struct {
	URL         string      `json:"url"`
	Title       string      `json:"title"`
	Excerpt     string      `json:"excerpt"`
	Note        string      `json:"note"`
	SourceType  SourceType  `json:"source_type"`
	FeedEntryID *uuid.UUID  `json:"source_feed_entry_id,omitempty"`
	IsPublic    bool        `json:"is_public"`
	TopicIDs    []uuid.UUID `json:"topic_ids"`
}

// Create handles POST /api/admin/bookmarks.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[CreateRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.URL == "" || req.Title == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "url and title are required")
		return
	}
	if req.SourceType == "" {
		req.SourceType = SourceManual
	}
	if !req.SourceType.Valid() {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid source_type")
		return
	}
	if req.SourceType == SourceRSS && req.FeedEntryID == nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "source_feed_entry_id required when source_type=rss")
		return
	}

	now := time.Now().UTC()
	var publishedAt *time.Time
	if req.IsPublic {
		publishedAt = &now
	}

	p := CreateParams{
		URL:         req.URL,
		URLHash:     hashURL(req.URL),
		Slug:        slugify(req.Title),
		Title:       req.Title,
		Excerpt:     req.Excerpt,
		Note:        req.Note,
		SourceType:  req.SourceType,
		FeedEntryID: req.FeedEntryID,
		CuratedBy:   "admin", // admin-authenticated path
		IsPublic:    req.IsPublic,
		PublishedAt: publishedAt,
		TopicIDs:    req.TopicIDs,
	}

	b, err := h.store.Create(r.Context(), &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: b})
}

// Delete handles DELETE /api/admin/bookmarks/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid bookmark id")
		return
	}
	if err := h.store.Delete(r.Context(), id); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

func parseFilter(r *http.Request) Filter {
	page, perPage := api.ParsePagination(r)
	f := Filter{Page: page, PerPage: perPage}
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.DateOnly, s); err == nil {
			f.Since = &t
		}
	}
	return f
}

func parseAdminFilter(r *http.Request) AdminFilter {
	page, perPage := api.ParsePagination(r)
	f := AdminFilter{Page: page, PerPage: perPage}
	if v := r.URL.Query().Get("is_public"); v != "" {
		b := v == "true"
		f.IsPublic = &b
	}
	return f
}

// hashURL produces the SHA-256 hex digest used as url_hash. The
// bookmark and feed_entries tables share this dedup identity, so the
// same canonicalisation must apply on both sides. For now we hash the
// URL verbatim — callers are expected to pass the already-canonical
// form. A central canonicaliser lives in a follow-up if mismatches show.
func hashURL(rawURL string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(rawURL)))
	return hex.EncodeToString(sum[:])
}

// slugify produces a URL-safe slug from a title. Simple transformation:
// lowercase, whitespace → '-', strip characters outside [a-z0-9-]. A
// more sophisticated slug policy (deduplication, collision handling)
// belongs in a dedicated helper if bookmark titles start colliding.
func slugify(title string) string {
	lower := strings.ToLower(strings.TrimSpace(title))
	var b strings.Builder
	b.Grow(len(lower))
	lastDash := false
	for _, r := range lower {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == ' ' || r == '-' || r == '_':
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	s := strings.TrimRight(b.String(), "-")
	if s == "" {
		return "bookmark"
	}
	return s
}
