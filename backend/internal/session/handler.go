package session

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/koopa0/blog-backend/internal/api"
)

// Handler serves session note REST endpoints.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a session note Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// List handles GET /api/admin/session-notes?date=YYYY-MM-DD&type=plan&days=7
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	endDate := time.Now()
	if d := q.Get("date"); d != "" {
		parsed, err := time.Parse(time.DateOnly, d)
		if err != nil {
			api.Error(w, http.StatusBadRequest, "INVALID_DATE", "date must be YYYY-MM-DD")
			return
		}
		endDate = parsed
	}

	days := 1
	if d := q.Get("days"); d != "" {
		v, err := strconv.Atoi(d)
		if err != nil || v < 1 {
			api.Error(w, http.StatusBadRequest, "INVALID_DAYS", "days must be a positive integer")
			return
		}
		if v > 30 {
			v = 30
		}
		days = v
	}

	startDate := endDate.AddDate(0, 0, -(days - 1))

	var noteType *string
	if t := q.Get("type"); t != "" {
		switch t {
		case "plan", "reflection", "context", "metrics":
			noteType = &t
		default:
			api.Error(w, http.StatusBadRequest, "INVALID_TYPE", "type must be plan, reflection, context, or metrics")
			return
		}
	}

	notes, err := h.store.NotesByDate(r.Context(), startDate, endDate, noteType)
	if err != nil {
		h.logger.Error("listing session notes", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list session notes")
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: notes})
}
