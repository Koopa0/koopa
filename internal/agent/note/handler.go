// handler.go exposes the agent_note runtime log over HTTP — the
// /coordination/agents/{name}/notes route, rendered as the notes tab
// on each agent's profile page.
//
// All filters are optional; defaults follow the MCP query_agent_notes
// shape (kind=*, since=-90d, until=today).

package note

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Koopa0/koopa/internal/api"
)

// Handler handles admin HTTP requests for agent notes.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns an agent-note Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// ListForAgent handles GET /api/admin/coordination/agents/{name}/notes.
// Query params: kind (comma-separated, single match), since, until.
// Date params are YYYY-MM-DD; invalid input resolves to the default
// 90-day window.
func (h *Handler) ListForAgent(w http.ResponseWriter, r *http.Request) {
	agentName := r.PathValue("name")
	if agentName == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "agent name is required")
		return
	}

	q := r.URL.Query()
	now := time.Now().UTC()
	since := now.AddDate(0, 0, -90)
	until := now

	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.DateOnly, v); err == nil {
			since = t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.DateOnly, v); err == nil {
			until = t.Add(24 * time.Hour)
		}
	}

	var kindFilter *Kind
	if v := q.Get("kind"); v != "" {
		// Comma-separated support mirrors the MCP signature, but the
		// current sqlc query accepts a single kind. Take the first match
		// and let the frontend widen later if needed.
		first := strings.TrimSpace(strings.SplitN(v, ",", 2)[0])
		if first != "" {
			k := Kind(first)
			switch k {
			case KindPlan, KindContext, KindReflection:
				kindFilter = &k
			default:
				api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid kind")
				return
			}
		}
	}

	rows, err := h.store.NotesInRange(r.Context(), since, until, kindFilter, &agentName)
	if err != nil {
		h.logger.Error("listing agent notes", "agent", agentName, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list agent notes")
		return
	}
	if rows == nil {
		rows = []Note{}
	}
	api.Encode(w, http.StatusOK, api.Response{Data: rows})
}
