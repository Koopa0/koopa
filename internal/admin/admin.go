// Package admin provides aggregate HTTP handlers for the admin frontend.
//
// Unlike per-feature handlers (content.Handler, task.Handler), these handlers
// cross multiple stores to serve workflow-driven aggregate views.
// Each endpoint maps to a frontend screen, not a database table.
//
// Uses internal/api for shared response helpers (Encode, Decode, Error, HandleError).
package admin

import (
	"log/slog"
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
