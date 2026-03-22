package note

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/koopa0/blog-backend/internal/api"
)

// Handler serves note search endpoints.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a note Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// Search handles GET /api/admin/notes?q=query&type=...&context=...&source=...&book=...&limit=20.
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if l, err := strconv.Atoi(v); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	q := r.URL.Query().Get("q")
	if q != "" {
		results, err := h.store.SearchByText(r.Context(), q, limit)
		if err != nil {
			h.logger.Error("searching notes by text", "query", q, "error", err)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to search notes")
			return
		}
		api.Encode(w, http.StatusOK, api.Response{Data: results})
		return
	}

	var f SearchFilter
	if v := r.URL.Query().Get("type"); v != "" {
		f.Type = &v
	}
	if v := r.URL.Query().Get("context"); v != "" {
		f.Context = &v
	}
	if v := r.URL.Query().Get("source"); v != "" {
		f.Source = &v
	}
	if v := r.URL.Query().Get("book"); v != "" {
		f.Book = &v
	}

	notes, err := h.store.SearchByFilters(r.Context(), f, limit)
	if err != nil {
		h.logger.Error("searching notes by filters", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to search notes")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: notes})
}

// DecisionLog handles GET /api/admin/decisions?project=slug&limit=50.
func (h *Handler) DecisionLog(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if l, err := strconv.Atoi(v); err == nil && l > 0 && l <= 200 {
			limit = l
		}
	}

	var contextFilter *string
	if v := r.URL.Query().Get("project"); v != "" {
		contextFilter = &v
	}

	notes, err := h.store.NotesByType(r.Context(), "decision-log", contextFilter, limit)
	if err != nil {
		h.logger.Error("querying decision log", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query decision log")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: notes})
}
