package bookmark

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/tag"
	"github.com/Koopa0/koopa/internal/topic"
	koopaurl "github.com/Koopa0/koopa/internal/url"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "bookmark not found"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT", Message: "bookmark conflict"},
}

// topicResolver is the subset of topic.Store the handler uses to map a
// caller-supplied topic_slug to its UUID. Defined consumer-side so the
// bookmark package does not import topic.Store directly.
type topicResolver interface {
	TopicBySlug(ctx context.Context, slug string) (*topic.Topic, error)
}

// tagResolver is the subset of tag.Store the handler uses to map
// caller-supplied raw tag strings into bookmark_tags rows. ResolveTags
// handles alias + slug matching; callers attach only entries whose TagID
// is non-nil (unmapped rawTags are dropped with a log line).
type tagResolver interface {
	ResolveTags(ctx context.Context, rawTags []string) []tag.Resolved
}

// Handler handles bookmark HTTP requests.
//
// The public surface exposes List and BySlug, mirroring
// content.Handler.List / content.Handler.BySlug. The admin surface adds
// AdminList, AdminGet, Create, Update, and Delete. topics / tags are
// optional — Create works without them (caller provides TopicIDs UUIDs
// directly); Update requires both to resolve topic_slug + tag names.
type Handler struct {
	store  *Store
	topics topicResolver
	tags   tagResolver
	logger *slog.Logger
}

// NewHandler returns a bookmark Handler. topics and tags may be nil in
// tests / non-admin wiring; Update returns 500 if they are nil at call time.
func NewHandler(store *Store, topics topicResolver, tags tagResolver, logger *slog.Logger) *Handler {
	return &Handler{store: store, topics: topics, tags: tags, logger: logger}
}

// PublicList handles GET /api/bookmarks — the is_public=true slice.
func (h *Handler) PublicList(w http.ResponseWriter, r *http.Request) {
	f := parsePublicFilter(r)
	bookmarks, total, err := h.store.PublicBookmarks(r.Context(), f)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(bookmarks, total, f.Page, f.PerPage))
}

// PublicBySlug handles GET /api/bookmarks/{slug}.
func (h *Handler) PublicBySlug(w http.ResponseWriter, r *http.Request) {
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

// List handles GET /api/admin/knowledge/bookmarks — full listing across
// both public and private rows.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := parseFilter(r)
	bookmarks, total, err := h.store.Bookmarks(r.Context(), f)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(bookmarks, total, f.Page, f.PerPage))
}

// Get handles GET /api/admin/knowledge/bookmarks/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
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
	URL            string      `json:"url"`
	Title          string      `json:"title"`
	Excerpt        string      `json:"excerpt"`
	Note           string      `json:"note"`
	CaptureChannel Channel     `json:"capture_channel"`
	FeedEntryID    *uuid.UUID  `json:"source_feed_entry_id,omitempty"`
	IsPublic       bool        `json:"is_public"`
	TopicIDs       []uuid.UUID `json:"topic_ids"`
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
	if req.CaptureChannel == "" {
		req.CaptureChannel = ChannelManual
	}
	if !req.CaptureChannel.Valid() {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid capture_channel")
		return
	}
	if req.CaptureChannel == ChannelRSS && req.FeedEntryID == nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "source_feed_entry_id required when capture_channel=rss")
		return
	}

	urlHash, err := koopaurl.Hash(req.URL)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", fmt.Sprintf("invalid url: %v", err))
		return
	}
	p := CreateParams{
		URL:            req.URL,
		URLHash:        urlHash,
		Slug:           slugify(req.Title),
		Title:          req.Title,
		Excerpt:        req.Excerpt,
		Note:           req.Note,
		CaptureChannel: req.CaptureChannel,
		FeedEntryID:    req.FeedEntryID,
		CuratedBy:      curatedByFromContext(r),
		IsPublic:       req.IsPublic,
		PublishedAt:    time.Now().UTC(),
		TopicIDs:       req.TopicIDs,
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	b, err := store.Create(r.Context(), &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: b})
}

// UpdateRequest is the admin Update payload. URL is deliberately absent —
// URL is the bookmark's identity (see bookmarks.url_hash UNIQUE). topic_slug
// full-replaces the topic set with the single named topic (empty string
// clears the topic set). tags, when present, full-replaces tag set; raw tags
// that resolve to an unmapped alias are silently dropped.
type UpdateRequest struct {
	Title     *string   `json:"title,omitempty"`
	Excerpt   *string   `json:"excerpt,omitempty"`
	Note      *string   `json:"note,omitempty"`
	TopicSlug *string   `json:"topic_slug,omitempty"`
	Tags      *[]string `json:"tags,omitempty"`
}

// Update handles PUT /api/admin/knowledge/bookmarks/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid bookmark id")
		return
	}
	req, err := api.Decode[UpdateRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	p := UpdateParams{Title: req.Title, Excerpt: req.Excerpt, Note: req.Note}
	if ok := h.resolveUpdateTopic(w, r, req.TopicSlug, &p); !ok {
		return
	}
	if ok := h.resolveUpdateTags(w, r, req.Tags, &p); !ok {
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	b, err := store.Update(r.Context(), id, p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: b})
}

// resolveUpdateTopic populates p.TopicIDs from the caller's topic_slug.
// Returns false after emitting the response when input is invalid.
func (h *Handler) resolveUpdateTopic(w http.ResponseWriter, r *http.Request, slug *string, p *UpdateParams) bool {
	if slug == nil {
		return true
	}
	if *slug == "" {
		empty := []uuid.UUID{}
		p.TopicIDs = &empty
		return true
	}
	if h.topics == nil {
		h.logger.Error("bookmark Update: topic resolver not wired")
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "topic resolver unavailable")
		return false
	}
	t, err := h.topics.TopicBySlug(r.Context(), *slug)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", fmt.Sprintf("unknown topic slug: %s", *slug))
		return false
	}
	ids := []uuid.UUID{t.ID}
	p.TopicIDs = &ids
	return true
}

// resolveUpdateTags populates p.TagIDs from the caller's raw tag strings.
// Raw tags that resolve to an unmapped alias are dropped with a log line.
func (h *Handler) resolveUpdateTags(w http.ResponseWriter, r *http.Request, tags *[]string, p *UpdateParams) bool {
	if tags == nil {
		return true
	}
	if h.tags == nil {
		h.logger.Error("bookmark Update: tag resolver not wired")
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "tag resolver unavailable")
		return false
	}
	resolved := h.tags.ResolveTags(r.Context(), *tags)
	ids := make([]uuid.UUID, 0, len(resolved))
	for _, res := range resolved {
		if res.TagID == nil {
			h.logger.Info("bookmark Update: dropping unmapped tag",
				"raw_tag", res.RawTag, "source", res.ResolutionSource)
			continue
		}
		ids = append(ids, *res.TagID)
	}
	p.TagIDs = &ids
	return true
}

// Delete handles DELETE /api/admin/bookmarks/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid bookmark id")
		return
	}
	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	if err := store.Delete(r.Context(), id); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

// curatedByFromContext returns the agent identity to stamp on a
// bookmark created via the admin HTTP path. Schema constrains
// bookmarks.curated_by via FK to agents(name), so the stamped value
// MUST be a registered agent — never claims.Email or "admin".
//
// The single source of truth is api.ActorMiddleware: cmd/app/main.go
// passes the literal "human" to the middleware, the middleware binds
// it to the koopa.actor GUC AND injects it into the request context,
// and this helper reads from there. Hardcoding "human" here (as a
// sibling literal to main's) would diverge silently under multi-admin
// — every handler's FK stamp would need updating individually. By
// reading from the middleware, multi-admin is a one-line change at
// main (resolve the actor from auth.ClaimsFromContext) and every
// curated_by / created_by / selected_by stamp site flips with it.
//
// The "human" fallback covers tests + non-admin paths where the
// middleware is not in play — the single-admin convention.
func curatedByFromContext(r *http.Request) string {
	if actor, ok := api.ActorFromContext(r.Context()); ok {
		return actor
	}
	return "human"
}

func parsePublicFilter(r *http.Request) PublicFilter {
	page, perPage := api.ParsePagination(r)
	f := PublicFilter{Page: page, PerPage: perPage}
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.DateOnly, s); err == nil {
			f.Since = &t
		}
	}
	return f
}

func parseFilter(r *http.Request) Filter {
	page, perPage := api.ParsePagination(r)
	f := Filter{Page: page, PerPage: perPage}
	if v := r.URL.Query().Get("is_public"); v != "" {
		b := v == "true"
		f.IsPublic = &b
	}
	return f
}

// hashURL moved to internal/url.Hash — single authoritative canonicaliser

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
