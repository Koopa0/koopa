package activity

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/koopa0/blog-backend/internal/api"
)

// maxEvents caps the number of events loaded for session/changelog grouping.
const maxEvents = 10_000

// Handler handles activity HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns an activity Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// Sessions handles GET /api/admin/activity/sessions.
// Query params: days (default 7, max 90).
func (h *Handler) Sessions(w http.ResponseWriter, r *http.Request) {
	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 && d <= 90 {
			days = d
		}
	}

	now := time.Now()
	start := now.AddDate(0, 0, -days)

	events, err := h.store.EventsByTimeRange(r.Context(), start, now)
	if err != nil {
		h.logger.Error("querying activity events for sessions", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query activity")
		return
	}

	if len(events) > maxEvents {
		events = events[:maxEvents]
	}

	sessions := GroupSessions(events)
	api.Encode(w, http.StatusOK, api.Response{Data: sessions})
}

// Changelog handles GET /api/admin/activity/changelog.
// Query params: days (default 30, max 90).
func (h *Handler) Changelog(w http.ResponseWriter, r *http.Request) {
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 && d <= 90 {
			days = d
		}
	}

	now := time.Now()
	start := now.AddDate(0, 0, -days)

	events, err := h.store.EventsByTimeRange(r.Context(), start, now)
	if err != nil {
		h.logger.Error("querying activity events for changelog", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query activity")
		return
	}

	const maxEvents = 10000
	if len(events) > maxEvents {
		events = events[:maxEvents]
	}

	changelog := GroupChangelog(events)
	api.Encode(w, http.StatusOK, api.Response{Data: changelog})
}
