// Copyright 2026 Koopa. All rights reserved.

package content

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "content not found"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT", Message: "content conflict"},
	{Target: ErrInvalidInput, Status: http.StatusBadRequest, Code: "BAD_REQUEST", Message: "invalid content input"},
	{Target: ErrInvalidState, Status: http.StatusBadRequest, Code: "INVALID_STATE", Message: "content not in required state for this transition"},
	{Target: ErrSourceRequired, Status: http.StatusBadRequest, Code: "SOURCE_REQUIRED", Message: "content source snapshot required before publication"},
}

// slugConflictBody is the structured 409 payload returned when a write
// collides with an existing slug. Callers (learning-studio via MCP, admin UI)
// use the existing row's id to decide whether this is an update path or a
// revisit needing a new slug.
type slugConflictBody struct {
	Error slugConflictDetail `json:"error"`
}

type slugConflictDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Slug      string `json:"slug"`
	ContentID string `json:"content_id"`
}

// Cache TTLs for pre-serialized feed responses.
// These caches expire on TTL only — no active invalidation on content writes.
// This is intentional: content mutations are infrequent and eventual consistency is acceptable.
const (
	rssTTL     = 10 * time.Minute
	sitemapTTL = 30 * time.Minute
)

// Handler handles content HTTP requests.
type Handler struct {
	store   *Store
	siteURL string
	logger  *slog.Logger

	feedCache *ristretto.Cache[string, []byte]
}

// NewHandler returns a content Handler. Admin mutation handlers rely on
// api.ActorMiddleware to supply the tx — see mustAdminTx.
func NewHandler(
	store *Store,
	siteURL string,
	logger *slog.Logger,
) *Handler {
	feedCache, _ := ristretto.NewCache(&ristretto.Config[string, []byte]{
		NumCounters: 100,     // 10x expected items (2 keys: "rss", "sitemap")
		MaxCost:     1 << 20, // 1 MB byte budget
		BufferItems: 64,
	})
	return &Handler{
		store:     store,
		siteURL:   siteURL,
		feedCache: feedCache,
		logger:    logger,
	}
}

// mustAdminTx extracts the request-scoped pgx.Tx supplied by
// api.ActorMiddleware. Admin mutation paths require a tx so audit
// triggers attribute writes to the real actor. A missing tx is a
// wiring bug — the handler returns 500 and logs a stable event key so
// the failure shows up in dashboards, not silently degraded audit
// rows with actor='human'.
func (h *Handler) mustAdminTx(w http.ResponseWriter, r *http.Request) (pgx.Tx, bool) {
	tx, ok := api.TxFromContext(r.Context())
	if !ok {
		h.logger.Error("admin mutation without tx",
			"event", "middleware_not_wired",
			"method", r.Method,
			"path", r.URL.Path)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
		return nil, false
	}
	return tx, true
}
