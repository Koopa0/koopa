package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/koopa0/koopa/internal/memory"
	"github.com/koopa0/koopa/internal/session"
)

// maxSearchQueryLength is the maximum allowed search query length in bytes.
const maxSearchQueryLength = 1000

// searchHandler holds dependencies for the search API endpoint.
type searchHandler struct {
	store  *session.Store
	logger *slog.Logger
}

// searchMessages handles GET /api/v1/search?q=...&limit=20&offset=0.
// Returns full-text search results across all sessions owned by the authenticated user.
func (h *searchHandler) searchMessages(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r, h.logger)
	if !ok {
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		WriteError(w, http.StatusBadRequest, "missing_query", "query parameter 'q' is required", h.logger)
		return
	}
	if len(query) > maxSearchQueryLength {
		WriteError(w, http.StatusBadRequest, "query_too_long", "query must be 1000 characters or fewer", h.logger)
		return
	}

	limit := min(parseIntParam(r, "limit", 20), 100)
	offset := parseIntParam(r, "offset", 0)
	if offset > 10000 {
		WriteError(w, http.StatusBadRequest, "invalid_offset", "offset must be 10000 or less", h.logger)
		return
	}

	results, total, err := h.store.SearchMessages(r.Context(), userID, query, limit, offset)
	if err != nil {
		h.logger.Error("searching messages", "error", err, "user_id", userID, "query_len", len(query))
		WriteError(w, http.StatusInternalServerError, "search_failed", "failed to search messages", h.logger)
		return
	}

	items := make([]searchResultItem, len(results))
	for i, sr := range results {
		items[i] = searchResultItem{
			SessionID:    sr.SessionID.String(),
			SessionTitle: sr.SessionTitle,
			MessageID:    sr.MessageID.String(),
			Role:         sr.Role,
			Snippet:      sr.Snippet,
			CreatedAt:    sr.CreatedAt.Format(time.RFC3339),
			Rank:         sr.Rank,
		}
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": total,
	}, h.logger)
}

// searchResultItem is the JSON representation of a search result.
type searchResultItem struct {
	SessionID    string  `json:"sessionId"`
	SessionTitle string  `json:"sessionTitle"`
	MessageID    string  `json:"messageId"`
	Role         string  `json:"role"`
	Snippet      string  `json:"snippet"`
	CreatedAt    string  `json:"createdAt"`
	Rank         float64 `json:"rank"`
}

// statsHandler holds dependencies for the stats API endpoint.
type statsHandler struct {
	sessionStore *session.Store
	memoryStore  *memory.Store // Optional: nil if memory is not configured.
	logger       *slog.Logger
}

// getStats handles GET /api/v1/stats — returns usage statistics.
func (h *statsHandler) getStats(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r, h.logger)
	if !ok {
		return
	}

	sessions, err := h.sessionStore.CountSessions(r.Context(), userID)
	if err != nil {
		h.logger.Error("counting sessions", "error", err, "user_id", userID)
		WriteError(w, http.StatusInternalServerError, "stats_failed", "failed to get stats", h.logger)
		return
	}

	messages, err := h.sessionStore.CountMessages(r.Context(), userID)
	if err != nil {
		h.logger.Error("counting messages", "error", err, "user_id", userID)
		WriteError(w, http.StatusInternalServerError, "stats_failed", "failed to get stats", h.logger)
		return
	}

	var memories int
	if h.memoryStore != nil {
		memories, err = h.memoryStore.ActiveCount(r.Context(), userID)
		if err != nil {
			h.logger.Error("counting memories", "error", err, "user_id", userID)
			WriteError(w, http.StatusInternalServerError, "stats_failed", "failed to get stats", h.logger)
			return
		}
	}

	WriteJSON(w, http.StatusOK, map[string]int{
		"sessions": sessions,
		"messages": messages,
		"memories": memories,
	}, h.logger)
}
