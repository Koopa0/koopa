// Copyright 2026 Koopa. All rights reserved.

// handler.go holds the daily plan HTTP handlers. The Today aggregate
// that composes across multiple domains lives in internal/today.

package daily

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/todo"
	"github.com/google/uuid"
)

// Handler handles daily plan HTTP requests. The admin Today aggregate is
// served out of internal/today; this Handler serves the per-date plan
// envelope that the Today HERO consumes directly.
//
// todos is the base (pool-bound) todo store. The plan-write path
// (PutPlan) rebinds both it and the daily store to the per-request tx so
// the delete-then-insert and its todo-state validations commit atomically,
// mirroring the MCP plan_day handler.
type Handler struct {
	store  *Store
	todos  *todo.Store
	logger *slog.Logger
}

// NewHandler returns a daily Handler. The todo store is required by the
// plan-write path to validate that each planned todo exists and is in
// state=todo; the read-only Plan handler does not touch it.
func NewHandler(store *Store, todos *todo.Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, todos: todos, logger: logger}
}

// PlanItem is the wire-level projection of a daily_plan_items row
// joined with its backing todo. Shape mirrors the row layout the Today
// HERO consumes.
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

// maxPlanPosition bounds the caller-supplied plan position so the int32
// cast cannot overflow. Mirrors the MCP plan_day ceiling — daily plans
// are small; this is a safety bound, not a product limit.
const maxPlanPosition = 100_000

// putPlanItem is one entry in the plan-write body. position is optional;
// when omitted (0) the handler uses the item's index so order follows the
// request.
type putPlanItem struct {
	TodoID   uuid.UUID `json:"todo_id"`
	Position *int      `json:"position,omitempty"`
}

// putPlanRequest is the body for PUT /api/admin/commitment/daily-plan.
type putPlanRequest struct {
	Date  *string       `json:"date,omitempty"`
	Items []putPlanItem `json:"items"`
}

// putPlanResponse is the wire shape returned by PutPlan. It mirrors the
// MCP plan_day output: the full new plan plus the todos genuinely
// displaced from a prior plan for this date.
type putPlanResponse struct {
	Date         string        `json:"date"`
	Items        []PlanItem    `json:"items"`
	Total        int           `json:"total"`
	ItemsRemoved []RemovedItem `json:"items_removed"`
}

// PutPlan handles PUT /api/admin/commitment/daily-plan — the human
// equivalent of the MCP plan_day tool. It is idempotent for the given
// date: it replaces the date's 'planned' rows with the supplied items in
// one transaction. Each todo MUST exist and be in state=todo (inbox-state
// todos are rejected — clarify them first). Empty items is a 400. The
// delete-then-insert runs atomically so a mid-loop validation failure
// leaves the previous plan intact.
func (h *Handler) PutPlan(w http.ResponseWriter, r *http.Request) {
	req, ok := decodePlanWriteRequest(w, r)
	if !ok {
		return
	}
	date, ok := parsePlanWriteDate(w, req.Date)
	if !ok {
		return
	}

	tx, ok := api.TxFromContext(r.Context())
	if !ok {
		h.logger.Error("daily plan write without tx",
			"event", "middleware_not_wired",
			"method", r.Method, "path", r.URL.Path)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
		return
	}

	txDaily := NewStore(tx)
	txTodos := h.todos.WithTx(tx)

	removed, derr := txDaily.DeletePlannedByDate(r.Context(), date)
	if derr != nil {
		h.logger.Error("clearing existing plan", "date", date, "error", derr)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to clear existing plan")
		return
	}

	caller := actorFromContext(r)
	for i := range req.Items {
		if !h.insertPlanItem(w, r, txDaily, txTodos, req.Items[i], i, date, caller) {
			return
		}
	}

	items, ferr := txDaily.ItemsByDate(r.Context(), date)
	if ferr != nil {
		h.logger.Error("fetching created plan items", "date", date, "error", ferr)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to read plan")
		return
	}

	resp := putPlanResponse{
		Date:         date.Format(time.DateOnly),
		Items:        make([]PlanItem, len(items)),
		Total:        len(items),
		ItemsRemoved: displacedFrom(removed, req.Items),
	}
	for i := range items {
		resp.Items[i] = wirePlanItem(&items[i])
	}
	api.Encode(w, http.StatusOK, api.Response{Data: resp})
}

// decodePlanWriteRequest decodes and applies the non-tx validations
// (non-empty items, per-item position bounds). On any failure it writes the
// HTTP error and returns ok=false; the caller MUST return immediately.
func decodePlanWriteRequest(w http.ResponseWriter, r *http.Request) (putPlanRequest, bool) {
	req, err := api.Decode[putPlanRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return putPlanRequest{}, false
	}
	if len(req.Items) == 0 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "items must contain at least one todo")
		return putPlanRequest{}, false
	}
	for i := range req.Items {
		if p := req.Items[i].Position; p != nil && (*p < 0 || *p > maxPlanPosition) {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "position out of range [0, 100000]")
			return putPlanRequest{}, false
		}
	}
	return req, true
}

// parsePlanWriteDate resolves the optional date, defaulting to today. On a
// malformed date it writes a 400 and returns ok=false.
func parsePlanWriteDate(w http.ResponseWriter, raw *string) (time.Time, bool) {
	if raw == nil || *raw == "" {
		return time.Now().UTC(), true
	}
	parsed, err := time.Parse(time.DateOnly, *raw)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid date format, use YYYY-MM-DD")
		return time.Time{}, false
	}
	return parsed, true
}

// insertPlanItem validates one item (todo exists + is not inbox-state) and
// inserts its plan row within the supplied tx-bound stores. i is the loop
// index, used as the position when the item omits one. On any failure it
// writes the HTTP error and returns ok=false; the caller MUST return so the
// tx rolls back and the previous plan is preserved.
func (h *Handler) insertPlanItem(w http.ResponseWriter, r *http.Request, txDaily *Store, txTodos *todo.Store, item putPlanItem, i int, date time.Time, caller string) bool {
	t, err := txTodos.ItemByID(r.Context(), item.TodoID)
	if err != nil {
		api.HandleError(w, h.logger, err, todoStoreErrors...)
		return false
	}
	if t.State == todo.StateInbox {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST",
			"todo "+item.TodoID.String()+" is in inbox state; clarify it to state=todo before planning")
		return false
	}
	pos := i
	if item.Position != nil {
		pos = *item.Position
	}
	if _, err := txDaily.Create(r.Context(), &CreateItemParams{
		PlanDate:   date,
		TodoID:     item.TodoID,
		SelectedBy: caller,
		Position:   int32(pos), // #nosec G115 -- validated to [0, maxPlanPosition] or the loop index; fits int32
	}); err != nil {
		if errors.Is(err, ErrItemResolved) {
			api.HandleError(w, h.logger, err, planItemErrors...)
			return false
		}
		h.logger.Error("creating plan item", "todo_id", item.TodoID, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to create plan item")
		return false
	}
	return true
}

// displacedFrom filters removed plan items down to those whose todo_id is
// NOT in the new plan. The delete-then-insert pattern produces a fresh
// plan_item id for every retained todo, so the raw removed list contains
// rows for todos the caller is keeping; reporting those as displaced would
// be wrong. The new items list is the source of truth for "still in the
// plan". Always returns a non-nil slice so the wire field is [] not null.
func displacedFrom(removed []RemovedItem, kept []putPlanItem) []RemovedItem {
	keptIDs := make(map[uuid.UUID]struct{}, len(kept))
	for i := range kept {
		keptIDs[kept[i].TodoID] = struct{}{}
	}
	out := make([]RemovedItem, 0, len(removed))
	for i := range removed {
		if _, stillThere := keptIDs[removed[i].TodoID]; !stillThere {
			out = append(out, removed[i])
		}
	}
	return out
}

// actorFromContext resolves the authenticated agent identity for the
// selected_by stamp, falling back to "human" outside the actor middleware.
func actorFromContext(r *http.Request) string {
	if a, ok := api.ActorFromContext(r.Context()); ok {
		return a
	}
	return "human"
}

// todoStoreErrors maps the todo sentinel errors the plan-write path can
// surface (a planned todo_id that does not exist) to HTTP responses.
var todoStoreErrors = []api.ErrMap{
	{Target: todo.ErrNotFound, Status: http.StatusBadRequest, Code: "TODO_NOT_FOUND", Message: "referenced todo not found"},
}

// planItemErrors maps the daily sentinel errors the plan-write insert can
// surface to HTTP responses.
var planItemErrors = []api.ErrMap{
	{Target: ErrItemResolved, Status: http.StatusConflict, Code: "PLAN_ITEM_RESOLVED", Message: "this todo is already resolved (done, deferred, or dropped) for that date and cannot be re-planned"},
}
