// Copyright 2026 Koopa. All rights reserved.

// handler.go holds the daily plan HTTP handlers. The Today aggregate
// that composes across multiple domains lives in internal/today.

package daily

import (
	"context"
	"errors"
	"fmt"
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
	loc    *time.Location
	logger *slog.Logger
}

// NewHandler returns a daily Handler. The todo store is required by the
// plan-write path to validate that each planned todo exists and is in
// state=todo; the read-only Plan handler does not touch it. loc is the owner's
// timezone for the default plan date (matches the MCP server); nil → UTC.
func NewHandler(store *Store, todos *todo.Store, loc *time.Location, logger *slog.Logger) *Handler {
	if loc == nil {
		loc = time.UTC
	}
	return &Handler{store: store, todos: todos, loc: loc, logger: logger}
}

// today returns the current date in the owner's timezone, at midnight. Mirrors
// mcp.Server.today so the daily plan's default date rolls at local midnight.
func (h *Handler) today() time.Time {
	now := time.Now().In(h.loc)
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, h.loc)
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
	date := h.today()
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
	today := h.today()
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
// one transaction. Each todo MUST exist and be in state=todo or in_progress,
// mirroring the plan_day allowlist (inbox/done/someday/archived/dismissed are
// rejected — clarify an inbox todo first). Empty items is a 400. The
// delete-then-insert runs atomically so a mid-loop validation failure
// leaves the previous plan intact.
func (h *Handler) PutPlan(w http.ResponseWriter, r *http.Request) {
	req, ok := decodePlanWriteRequest(w, r)
	if !ok {
		return
	}
	date, ok := h.parsePlanWriteDate(w, req.Date)
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

	ids := make([]uuid.UUID, len(req.Items))
	for i := range req.Items {
		ids[i] = req.Items[i].TodoID
	}
	todosByID, terr := fetchTodosByID(r.Context(), txTodos, ids)
	if terr != nil {
		h.logger.Error("fetching planned todos", "error", terr)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to read todos")
		return
	}

	caller := actorFromContext(r)
	params := make([]CreateItemParams, len(req.Items))
	for i := range req.Items {
		p, ok := h.validatePlanItem(w, todosByID, req.Items[i], i, date, caller)
		if !ok {
			return
		}
		params[i] = p
	}

	for i, result := range txDaily.CreateAll(r.Context(), params) {
		if result.Err == nil {
			continue
		}
		if errors.Is(result.Err, ErrItemResolved) {
			api.HandleError(w, h.logger, result.Err, planItemErrors...)
			return
		}
		h.logger.Error("creating plan item", "todo_id", req.Items[i].TodoID, "error", result.Err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to create plan item")
		return
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
func (h *Handler) parsePlanWriteDate(w http.ResponseWriter, raw *string) (time.Time, bool) {
	if raw == nil || *raw == "" {
		return h.today(), true
	}
	parsed, err := time.Parse(time.DateOnly, *raw)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid date format, use YYYY-MM-DD")
		return time.Time{}, false
	}
	return parsed, true
}

// fetchTodosByID resolves every planned todo_id in one round trip, keyed by
// id, so insertPlanItem can validate each item without a per-item query. This
// snapshot is taken once before the insert loop, so a later item's read and
// its own insert are further apart in time than a fresh per-item read would
// be — under Read Committed with no row lock, a concurrent state UPDATE to a
// not-yet-inserted item in this narrow window would go unnoticed (a DELETE
// still surfaces as an FK violation on insert either way). Acceptable for
// this single-operator admin flow; revisit with FOR UPDATE if this handler
// ever serves concurrent writers.
func fetchTodosByID(ctx context.Context, s *todo.Store, ids []uuid.UUID) (map[uuid.UUID]todo.Item, error) {
	items, err := s.ItemsByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("fetching todos by id: %w", err)
	}
	byID := make(map[uuid.UUID]todo.Item, len(items))
	for i := range items {
		byID[items[i].ID] = items[i]
	}
	return byID, nil
}

// validatePlanItem checks one item (todo exists + is not inbox-state) and
// builds its CreateItemParams. todosByID is the batch-fetched lookup built
// once by fetchTodosByID before the loop. i is the loop index, used as the
// position when the item omits one. On any failure it writes the HTTP
// error and returns ok=false; the caller MUST return without writing
// anything — validation is pure in-memory, so nothing has touched the tx
// yet and the previous plan is naturally preserved.
func (h *Handler) validatePlanItem(w http.ResponseWriter, todosByID map[uuid.UUID]todo.Item, item putPlanItem, i int, date time.Time, caller string) (CreateItemParams, bool) {
	t, ok := todosByID[item.TodoID]
	if !ok {
		api.HandleError(w, h.logger, todo.ErrNotFound, todoStoreErrors...)
		return CreateItemParams{}, false
	}
	if t.State != todo.StateTodo && t.State != todo.StateInProgress {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST",
			"todo "+item.TodoID.String()+" is in state "+string(t.State)+
				" — only todo or in_progress items can be planned (clarify an inbox todo first; done/someday/archived are not today's work)")
		return CreateItemParams{}, false
	}
	pos := i
	if item.Position != nil {
		pos = *item.Position
	}
	return CreateItemParams{
		PlanDate:   date,
		TodoID:     item.TodoID,
		SelectedBy: caller,
		Position:   int32(pos), // #nosec G115 -- validated to [0, maxPlanPosition] or the loop index; fits int32
	}, true
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
