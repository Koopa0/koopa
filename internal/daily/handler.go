// handler.go holds the daily plan HTTP handlers. The Today aggregate
// that composes across multiple domains lives in internal/today.

package daily

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/Koopa0/koopa/internal/api"
)

// Handler handles daily plan HTTP requests. The admin Today aggregate is
// served out of internal/today; this Handler serves the per-date plan
// envelope that the Today HERO and legacy now-page dashboard consume
// directly.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a daily Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// PlanItem is the wire-level projection of a daily_plan_items row
// joined with its backing todo. Shape mirrors the row layout consumed
// by the now-page dashboard.
type PlanItem struct {
	ID          string  `json:"id"`
	TodoID      string  `json:"todo_id"`
	Title       string  `json:"title"`
	Priority    *string `json:"priority,omitempty"`
	State       Status  `json:"state"`
	Reason      *string `json:"reason,omitempty"`
	DueDate     *string `json:"due_date,omitempty"`
	CompletedAt *string `json:"completed_at,omitempty"`
	SelectedBy  string  `json:"selected_by"`
}

// PlanResponse is the wire shape for GET /api/admin/commitment/daily-plan.
type PlanResponse struct {
	Date         string     `json:"date"`
	Items        []PlanItem `json:"items"`
	Total        int        `json:"total"`
	Done         int        `json:"done"`
	OverdueCount int        `json:"overdue_count"`
}

// Plan handles GET /api/admin/commitment/daily-plan.
// Query params: date (YYYY-MM-DD; defaults to server today).
func (h *Handler) Plan(w http.ResponseWriter, r *http.Request) {
	date := time.Now().UTC()
	if d := r.URL.Query().Get("date"); d != "" {
		parsed, err := time.Parse(time.DateOnly, d)
		if err != nil {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid date format, use YYYY-MM-DD")
			return
		}
		date = parsed
	}

	rows, err := h.store.ItemsByDate(r.Context(), date)
	if err != nil {
		h.logger.Error("listing daily plan", "date", date, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list daily plan")
		return
	}

	resp := PlanResponse{
		Date:  date.Format(time.DateOnly),
		Items: make([]PlanItem, len(rows)),
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for i := range rows {
		resp.Items[i] = wirePlanItem(&rows[i])
		if rows[i].Status == StatusDone {
			resp.Done++
		}
		if rows[i].TodoDue != nil && rows[i].Status != StatusDone && rows[i].TodoDue.Before(today) {
			resp.OverdueCount++
		}
	}
	resp.Total = len(rows)

	api.Encode(w, http.StatusOK, api.Response{Data: resp})
}

func wirePlanItem(r *Item) PlanItem {
	p := PlanItem{
		ID:         r.ID.String(),
		TodoID:     r.TodoID.String(),
		Title:      r.TodoTitle,
		Priority:   r.TodoPriority,
		State:      r.Status,
		Reason:     r.Reason,
		SelectedBy: r.SelectedBy,
	}
	if r.TodoDue != nil {
		due := r.TodoDue.Format(time.DateOnly)
		p.DueDate = &due
	}
	return p
}
