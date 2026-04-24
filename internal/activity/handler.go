package activity

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Koopa0/koopa/internal/api"
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

// Changelog handles GET /api/admin/coordination/activity.
// Query params: days (default 30, max 90), project, source (entity_type),
// actor (comma-separated allowlist).
func (h *Handler) Changelog(w http.ResponseWriter, r *http.Request) {
	days := parseDaysParam(r.URL.Query().Get("days"), 30, 90)
	now := time.Now()
	start := now.AddDate(0, 0, -days)

	source := optionalStringParam(r.URL.Query().Get("source"))
	project := optionalStringParam(r.URL.Query().Get("project"))
	actors := commaSplit(r.URL.Query().Get("actor"))

	events, err := h.loadChangelogEvents(r.Context(), start, now, source, project, actors)
	if err != nil {
		h.logger.Error("querying activity events for changelog", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query activity")
		return
	}

	changelog := GroupChangelog(events)
	api.Encode(w, http.StatusOK, api.Response{Data: ChangelogResponse{Days: changelog}})
}

// loadChangelogEvents picks the filtered or unfiltered query based on
// whether any filter is non-empty, capping the result at maxEvents.
func (h *Handler) loadChangelogEvents(ctx context.Context, start, end time.Time, source, project *string, actors []string) ([]Event, error) {
	if source != nil || project != nil || len(actors) > 0 {
		return h.store.EventsByFilters(ctx, start, end, source, project, actors, maxEvents)
	}
	events, err := h.store.EventsByTimeRange(ctx, start, end)
	if err != nil {
		return nil, err
	}
	if len(events) > maxEvents {
		events = events[:maxEvents]
	}
	return events, nil
}

func parseDaysParam(raw string, def, maxDays int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n > maxDays {
		return def
	}
	return n
}

func optionalStringParam(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func commaSplit(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
