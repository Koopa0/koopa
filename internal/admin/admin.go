// Package admin provides aggregate HTTP handlers for the admin frontend.
//
// Unlike per-feature handlers (content.Handler, task.Handler), these handlers
// cross multiple stores to serve workflow-driven aggregate views.
// Each endpoint maps to a frontend screen, not a database table.
package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/daily"
	"github.com/Koopa0/koopa0.dev/internal/directive"
	"github.com/Koopa0/koopa0.dev/internal/feed/entry"
	"github.com/Koopa0/koopa0.dev/internal/goal"
	"github.com/Koopa0/koopa0.dev/internal/insight"
	"github.com/Koopa0/koopa0.dev/internal/journal"
	"github.com/Koopa0/koopa0.dev/internal/learning"
	"github.com/Koopa0/koopa0.dev/internal/plan"
	"github.com/Koopa0/koopa0.dev/internal/project"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// Handler provides aggregate admin API endpoints.
type Handler struct {
	tasks      *task.Store
	journal    *journal.Store
	dayplan    *daily.Store
	contents   *content.Store
	projects   *project.Store
	goals      *goal.Store
	directives *directive.Store
	insights   *insight.Store
	learn      *learning.Store
	plans      *plan.Store
	entries    *entry.Store

	loc       *time.Location
	logger    *slog.Logger
	proposals sync.Map // proposal_id → proposalEntry
}

// proposalEntry holds a cached proposal for the two-step propose→commit flow.
type proposalEntry struct {
	entityType string
	data       any
}

// NewHandler creates an admin Handler with all required stores.
func NewHandler(pool *pgxpool.Pool, loc *time.Location, logger *slog.Logger) *Handler {
	if pool == nil {
		panic("admin: nil pool")
	}
	if loc == nil {
		loc = time.UTC
	}
	return &Handler{
		tasks:      task.NewStore(pool),
		journal:    journal.NewStore(pool),
		dayplan:    daily.NewStore(pool),
		contents:   content.NewStore(pool),
		projects:   project.NewStore(pool),
		goals:      goal.NewStore(pool),
		directives: directive.NewStore(pool),
		insights:   insight.NewStore(pool),
		learn:      learning.NewStore(pool),
		plans:      plan.NewStore(pool),
		entries:    entry.NewStore(pool),
		loc:        loc,
		logger:     logger,
	}
}

// today returns the current date in the configured timezone.
func (h *Handler) today() time.Time {
	now := time.Now().In(h.loc)
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, h.loc)
}

// maxBodySize is the maximum request body size (1 MiB).
const maxBodySize = 1 << 20

// decodeBody reads and decodes a JSON request body with size limiting.
func decodeBody[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return v, false
	}
	return v, true
}

// writeJSON encodes v as JSON and writes it with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Connection probably closed — nothing useful to do.
		_ = err // best-effort
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// storeProposal caches a proposal for the two-step propose→commit flow.
func (h *Handler) storeProposal(id, entityType string, data any) {
	h.proposals.Store(id, proposalEntry{entityType: entityType, data: data})
}

// loadProposal retrieves a cached proposal by ID.
func (h *Handler) loadProposal(id string) (any, bool) {
	v, ok := h.proposals.LoadAndDelete(id)
	if !ok {
		return nil, false
	}
	e, ok2 := v.(proposalEntry)
	if !ok2 {
		return nil, false
	}
	return e.data, true
}
