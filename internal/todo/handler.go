// Copyright 2026 Koopa. All rights reserved.

// handler.go holds the admin HTTP handlers for personal GTD todos.
// Every mutation route runs under adminMid in cmd/app/routes.go so the
// per-request tx in context carries koopa.actor and the audit trigger
// records the real mutator.
//
// State transitions go through POST {id}/advance (clarify, start,
// complete, defer, activate, drop) instead of riding PUT so every state
// change surfaces as a distinct audit event. PUT mutates scalar fields
// only — state transitions via PUT return 400.

package todo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
)

// storeErrors maps todo sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "todo not found"},
	{Target: ErrInvalidInput, Status: http.StatusBadRequest, Code: "BAD_REQUEST", Message: "invalid todo input"},
}

// ErrInvalidTransition is returned by Advance when the caller supplies
// an unknown action. Defined at the handler to avoid leaking HTTP
// vocabulary into the store.
var ErrInvalidTransition = errors.New("todo: invalid transition")

// Handler handles admin HTTP requests for todos.
type Handler struct {
	store  *Store
	loc    *time.Location
	logger *slog.Logger
}

// NewHandler returns a todo Handler. loc is the owner's timezone — the day
// boundary for "today" (recurring due dates, occurrence stamps) so the admin
// rolls over at local midnight, matching the MCP server (cmd/mcp wires the
// same zone). A nil loc falls back to UTC.
func NewHandler(store *Store, loc *time.Location, logger *slog.Logger) *Handler {
	if loc == nil {
		loc = time.UTC
	}
	return &Handler{store: store, loc: loc, logger: logger}
}

// today returns the current date in the owner's timezone, at midnight. Mirrors
// mcp.Server.today so the HTTP admin and the MCP surface agree on the day.
func (h *Handler) today() time.Time {
	now := time.Now().In(h.loc)
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, h.loc)
}

// mustAdminTx extracts the per-request tx. A missing tx is a wiring
// bug, not a client error — surface as 500 and log.
func (h *Handler) mustAdminTx(w http.ResponseWriter, r *http.Request) (store *Store, ok bool) {
	tx, ok := api.TxFromContext(r.Context())
	if !ok {
		h.logger.Error("todo admin mutation without tx",
			"event", "middleware_not_wired",
			"method", r.Method, "path", r.URL.Path)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
		return nil, false
	}
	return h.store.WithTx(tx), true
}

// listResponse is the wire shape for a todo list entry. Extends Item
// with project_title joined from the projects table so the UI does not
// need a second round-trip to resolve names.
type listResponse struct {
	Item
	ProjectTitle string `json:"project_title,omitempty"`
}

// List handles GET /api/admin/commitment/todos.
// Query params: state (single value or comma-separated list, every
// element validated against the state enum), project (uuid), priority,
// energy, q, per_page, due_before (YYYY-MM-DD), sort. due_before is applied
// in Go after the SQL query returns. Unknown sort values silently fall
// back to the default ordering (due → priority → created_at).
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var states []string
	if raw := q.Get("state"); raw != "" {
		for s := range strings.SplitSeq(raw, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if !validState(s) {
				api.Error(w, http.StatusBadRequest, "BAD_REQUEST",
					"state must be a comma-separated subset of {inbox, todo, in_progress, done, someday, archived, dismissed}")
				return
			}
			states = append(states, s)
		}
	}
	project := q.Get("project")
	priority := q.Get("priority")
	energy := q.Get("energy")
	search := q.Get("q")
	sort := q.Get("sort")
	switch sort {
	case "", "due", "priority", "created_at":
		// allowed
	default:
		sort = ""
	}
	limit := 100
	if v := q.Get("per_page"); v != "" {
		if n := parsePosInt(v, 100); n > 0 && n <= 200 {
			limit = n
		}
	}

	rows, err := h.store.BacklogItems(r.Context(), states, project, energy, priority, search, sort, limit)
	if err != nil {
		h.logger.Error("listing todos", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list todos")
		return
	}

	if v := q.Get("due_before"); v != "" {
		if cutoff, err := time.Parse(time.DateOnly, v); err == nil {
			rows = filterDueBefore(rows, cutoff)
		}
	}

	out := make([]listResponse, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = listResponse{
			Item: Item{
				ID:            r.ID,
				Title:         r.Title,
				State:         r.State,
				Due:           r.Due,
				Energy:        r.Energy,
				Priority:      r.Priority,
				RecurInterval: r.RecurInterval,
				RecurUnit:     r.RecurUnit,
				Description:   r.Description,
				CreatedBy:     r.CreatedBy,
				CreatedAt:     r.CreatedAt,
				UpdatedAt:     r.UpdatedAt,
			},
			ProjectTitle: r.ProjectTitle,
		}
	}
	api.Encode(w, http.StatusOK, api.Response{Data: out})
}

// recurringResponse is the wire shape for GET /todos/recurring. Both arrays are
// non-nil so an empty result serializes [] not null. DueToday is the compute-on-
// read occurrences due today; All is every active recurring schedule, for the
// routines overview (manage-all view).
type recurringResponse struct {
	DueToday []Item `json:"due_today"`
	All      []Item `json:"all"`
}

// Recurring handles GET /api/admin/commitment/todos/recurring — the recurring
// todos whose occurrence is due today, computed on read from each todo's
// recurrence rule and last completion. today is the server's day boundary,
// matching the daily-plan read. There is no "overdue" bucket: compute-on-read
// has no stored next-due to fall behind — a recurrence is either due today or
// it is not.
func (h *Handler) Recurring(w http.ResponseWriter, r *http.Request) {
	today := h.today()

	dueToday, err := h.store.RecurringItemsDueToday(r.Context(), today)
	if err != nil {
		h.logger.Error("listing recurring todos due today", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list recurring todos")
		return
	}

	all, err := h.store.AllRecurringItems(r.Context())
	if err != nil {
		h.logger.Error("listing all recurring todos", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list recurring todos")
		return
	}

	resp := recurringResponse{DueToday: ensureItems(dueToday), All: ensureItems(all)}
	api.Encode(w, http.StatusOK, api.Response{Data: resp})
}

// historyDefaultWindow is the look-back applied when ?since= is omitted.
const historyDefaultWindow = 30 * 24 * time.Hour

// historyMaxResults bounds the search-path result set per api conventions
// (limit default 20, max 100).
const (
	historyDefaultLimit = 20
	historyMaxLimit     = 100
)

// History handles GET /api/admin/commitment/todos/history — the Complete
// ("已了結") view. With ?q= it searches the resolved set (done + dropped +
// recurring occurrences) by title/description; without it, it lists the same
// resolved set since the cutoff. Query params: since (YYYY-MM-DD, default 30d
// ago), q, limit (1-100, default 20).
func (h *Handler) History(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	since := time.Now().UTC().Add(-historyDefaultWindow)
	if v := q.Get("since"); v != "" {
		parsed, err := time.Parse(time.DateOnly, v)
		if err != nil {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid since format, use YYYY-MM-DD")
			return
		}
		since = parsed
	}

	limit := historyDefaultLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > historyMaxLimit {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "limit must be between 1 and 100")
			return
		}
		limit = n
	}

	// Search path: ?q= present → search the SAME resolved set as the default
	// view (done + dropped + recurring occurrences), title/description match,
	// within the since window. Matching the default view's arms is what makes a
	// dropped or recurring resolution searchable in the Complete tab.
	if query := q.Get("q"); query != "" {
		results, err := h.store.SearchResolvedItems(r.Context(), query, since, int32(limit)) // #nosec G115 -- limit bounded to [1, 100]
		if err != nil {
			h.logger.Error("searching todo history", "error", err)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to search todo history")
			return
		}
		if results == nil {
			results = []ResolvedDetail{}
		}
		api.Encode(w, http.StatusOK, api.Response{Data: results})
		return
	}

	// Resolved-since path: the default Complete-tab view — done, dropped, and
	// recurring routines' recent occurrences.
	resolved, err := h.store.ResolvedItemsDetailSince(r.Context(), since)
	if err != nil {
		h.logger.Error("listing resolved todo history", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list todo history")
		return
	}
	if resolved == nil {
		resolved = []ResolvedDetail{}
	}
	api.Encode(w, http.StatusOK, api.Response{Data: resolved})
}

// ensureItems returns a non-nil slice so empty results serialize as [].
func ensureItems(items []Item) []Item {
	if items == nil {
		return []Item{}
	}
	return items
}

// parseDueDate converts an optional YYYY-MM-DD string into a *time.Time.
// nil/empty input returns (nil, nil) — caller treats as "unchanged".
func parseDueDate(s *string) (*time.Time, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.DateOnly, *s)
	if err != nil {
		return nil, errors.New("invalid due_date; expected YYYY-MM-DD")
	}
	return &t, nil
}

// filterDueBefore returns rows whose Due is set and strictly before the
// end of cutoff (exclusive on the next day boundary).
func filterDueBefore(rows []PendingDetail, cutoff time.Time) []PendingDetail {
	end := cutoff.Add(24 * time.Hour)
	out := rows[:0]
	for i := range rows {
		if rows[i].Due != nil && rows[i].Due.Before(end) {
			out = append(out, rows[i])
		}
	}
	return out
}

// Get handles GET /api/admin/commitment/todos/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid todo id")
		return
	}
	item, err := h.store.ItemByID(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: item})
}

// createRequest is the POST body for Create. State defaults to inbox
// when omitted (frictionless capture); callers that know all fields can
// pass state=todo to skip the inbox clarify step.
type createRequest struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	State       State      `json:"state,omitempty"`
	ProjectID   *uuid.UUID `json:"project_id,omitempty"`
	Priority    *string    `json:"priority,omitempty"`
	Energy      *string    `json:"energy,omitempty"`
	DueDate     *string    `json:"due_date,omitempty"`
}

// Create handles POST /api/admin/commitment/todos.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[createRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title is required")
		return
	}
	if req.Priority != nil && !validPriority(*req.Priority) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid priority")
		return
	}
	if req.Energy != nil && !validEnergy(*req.Energy) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid energy")
		return
	}

	var due *time.Time
	if req.DueDate != nil && *req.DueDate != "" {
		t, err := time.Parse(time.DateOnly, *req.DueDate)
		if err != nil {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid due_date; expected YYYY-MM-DD")
			return
		}
		due = &t
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}

	actor := actorFromContext(r)
	item, err := store.Create(r.Context(), &CreateParams{
		Title:       req.Title,
		Description: req.Description,
		ProjectID:   req.ProjectID,
		Due:         due,
		Energy:      req.Energy,
		Priority:    req.Priority,
		CreatedBy:   actor,
	})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	// Create always starts in inbox at the store layer. If the caller
	// asked for state=todo, clarify up immediately so the wire response
	// reflects the requested state.
	if req.State == StateTodo {
		promoted, err := store.Clarify(r.Context(), item.ID, &ClarifyParams{
			Priority: req.Priority,
			Energy:   req.Energy,
			Due:      due,
		})
		if err != nil {
			// Keep the created item — the clarify failure is a soft signal,
			// not a user-visible failure.
			h.logger.Warn("todo Create: state=todo clarify failed", "id", item.ID, "error", err)
		} else {
			item = promoted
		}
	}

	api.Encode(w, http.StatusCreated, api.Response{Data: item})
}

// updateRequest is the PUT body. State is intentionally absent — use
// /advance for transitions.
type updateRequest struct {
	Title       *string    `json:"title,omitempty"`
	Description *string    `json:"description,omitempty"`
	ProjectID   *uuid.UUID `json:"project_id,omitempty"`
	Priority    *string    `json:"priority,omitempty"`
	Energy      *string    `json:"energy,omitempty"`
	DueDate     *string    `json:"due_date,omitempty"`
}

// Update handles PUT /api/admin/commitment/todos/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid todo id")
		return
	}
	req, err := api.Decode[updateRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	// Title is optional on update (nil = unchanged), but a present-yet-blank
	// title violates chk_todo_title_not_blank — reject it here so the asymmetry
	// with Create (which requires a non-blank title) does not let a blank
	// through to a 500 at the DB boundary.
	if req.Title != nil && strings.TrimSpace(*req.Title) == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title must not be blank")
		return
	}
	if req.Priority != nil && !validPriority(*req.Priority) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid priority")
		return
	}
	if req.Energy != nil && !validEnergy(*req.Energy) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid energy")
		return
	}

	// Store.UpdateParams.Due uses nil to mean "unchanged", so an empty-
	// string due_date is a no-op. Callers wanting to clear a due date go
	// through the advance endpoint.
	due, err := parseDueDate(req.DueDate)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	item, err := store.Update(r.Context(), &UpdateParams{
		ID:          id,
		Title:       req.Title,
		Description: req.Description,
		ProjectID:   req.ProjectID,
		Priority:    req.Priority,
		Energy:      req.Energy,
		Due:         due,
	})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: item})
}

// advanceRequest carries the GTD advance action: clarify, start,
// complete, defer, activate, or drop. 'drop' removes the row — see
// storeDelete comment.
type advanceRequest struct {
	Action string `json:"action"`
}

// Advance handles POST /api/admin/commitment/todos/{id}/advance.
// Returns 400 INVALID_TRANSITION for unknown actions or when the
// current state does not accept the requested action at the store layer.
func (h *Handler) Advance(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid todo id")
		return
	}
	req, err := api.Decode[advanceRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}

	var (
		item       *Item
		actionErr  error
		shouldLoad = true
	)
	switch req.Action {
	case "clarify":
		item, actionErr = store.Clarify(r.Context(), id, &ClarifyParams{})
		shouldLoad = false
	case "start":
		actionErr = store.Start(r.Context(), id)
	case "complete":
		// advanceComplete returns the fresh item directly — no reload needed.
		item, actionErr = h.advanceComplete(r.Context(), store, id)
		shouldLoad = false
	case "defer":
		actionErr = store.Defer(r.Context(), id)
	case "activate":
		h.advanceActivate(w, r, store, id)
		return
	case "drop":
		// drop hard-deletes an inbox-state row. Non-inbox rows surface
		// ErrNotFound — the caller must pick defer explicitly rather
		// than having the server silently rewrite the action.
		if err := store.Delete(r.Context(), id); err != nil {
			if errors.Is(err, ErrNotFound) {
				api.Error(w, http.StatusBadRequest, "INVALID_TRANSITION",
					"drop requires inbox state; use defer for other states")
				return
			}
			api.HandleError(w, h.logger, err, storeErrors...)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		api.Error(w, http.StatusBadRequest, "INVALID_TRANSITION",
			"action must be one of: clarify, start, complete, defer, activate, drop")
		return
	}

	if actionErr != nil {
		api.HandleError(w, h.logger, actionErr, storeErrors...)
		return
	}

	if shouldLoad {
		item, err = store.ItemByID(r.Context(), id)
		if err != nil {
			api.HandleError(w, h.logger, err, storeErrors...)
			return
		}
	}
	api.Encode(w, http.StatusOK, api.Response{Data: item})
}

// advanceComplete completes a todo and returns the updated item (so the caller
// need not re-load it). A recurring todo completes today's occurrence —
// stamping last_completed_on while keeping it recurring — so the admin complete
// button matches the MCP resolve_todo semantics and never kills a recurrence
// (UpdateTodoItemState → done would). A non-recurring todo completes terminally.
// today uses the server day boundary, mirroring Recurring.
func (h *Handler) advanceComplete(ctx context.Context, store *Store, id uuid.UUID) (*Item, error) {
	item, err := store.ItemByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if item.IsRecurring() {
		today := h.today()
		if err := store.CompleteOccurrenceByID(ctx, id, today); err != nil {
			return nil, err
		}
		// Reflect the occurrence stamp on the already-loaded item — its state
		// is unchanged — so no second round-trip is needed for the response.
		item.LastCompletedOn = &today
		return item, nil
	}
	return store.Complete(ctx, id)
}

// recurrenceRequest is the PUT body for Recurrence. Exactly one of weekdays,
// interval+unit, or clear must be set — mirrors set_todo_recurrence.
type recurrenceRequest struct {
	Weekdays []string `json:"weekdays,omitempty"`
	Interval *int     `json:"interval,omitempty"`
	Unit     *string  `json:"unit,omitempty"`
	Clear    bool     `json:"clear,omitempty"`
}

// Recurrence handles PUT /api/admin/commitment/todos/{id}/recurrence — the
// admin (owner) set/clear of a todo's recurrence. weekday-mode (weekdays:
// mon..sun), interval-mode (interval + unit: days/weeks/months/years), or
// clear=true to make it a one-shot again. NOT caller-scoped (unlike the MCP
// set_todo_recurrence) — the owner manages any todo from the admin UI.
func (h *Handler) Recurrence(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid todo id")
		return
	}
	req, err := api.Decode[recurrenceRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	rec, err := parseRecurrence(&req)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	if err := store.SetRecurrenceByID(r.Context(), id, rec); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	item, err := store.ItemByID(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: item})
}

// weekdayBits maps a lowercase weekday abbreviation to its bit in the
// recur_weekdays mask (Mon=bit0 .. Sun=bit6, matching ISODOW-1). Mirrors the
// agent-side map in internal/mcp/recurrence.go — kept separate so the admin
// path carries no dependency on the MCP package.
var weekdayBits = map[string]int16{
	"mon": 1, "tue": 2, "wed": 4, "thu": 8, "fri": 16, "sat": 32, "sun": 64,
}

// maxRecurInterval bounds interval-mode so the int32 cast cannot overflow.
const maxRecurInterval = 10_000

func validRecurUnit(u string) bool {
	switch u {
	case "days", "weeks", "months", "years":
		return true
	default:
		return false
	}
}

// parseRecurrence validates that exactly one mode is requested (weekdays,
// interval+unit, or clear) and converts it to a Recurrence. The mutual
// exclusivity mirrors chk_todo_recurrence, validated here so the caller gets a
// 400, not a CHECK error at the DB boundary.
func parseRecurrence(req *recurrenceRequest) (Recurrence, error) {
	hasWeekdays := len(req.Weekdays) > 0
	hasInterval := req.Interval != nil || req.Unit != nil

	switch {
	case !exactlyOne(hasWeekdays, hasInterval, req.Clear):
		return Recurrence{}, errors.New("specify exactly one of: weekdays, interval+unit, or clear")
	case req.Clear:
		return Recurrence{}, nil
	case hasWeekdays:
		return weekdayRecurrence(req.Weekdays)
	default:
		return intervalRecurrence(req.Interval, req.Unit)
	}
}

// exactlyOne reports whether exactly one of the flags is set.
func exactlyOne(flags ...bool) bool {
	set := 0
	for _, f := range flags {
		if f {
			set++
		}
	}
	return set == 1
}

// weekdayRecurrence converts weekday abbreviations to a weekday-mode Recurrence.
func weekdayRecurrence(weekdays []string) (Recurrence, error) {
	var mask int16
	for _, day := range weekdays {
		bit, ok := weekdayBits[strings.ToLower(strings.TrimSpace(day))]
		if !ok {
			return Recurrence{}, fmt.Errorf("unknown weekday %q (use mon,tue,wed,thu,fri,sat,sun)", day)
		}
		mask |= bit
	}
	if mask == 0 {
		return Recurrence{}, errors.New("weekdays must name at least one day")
	}
	return Recurrence{Weekdays: &mask}, nil
}

// intervalRecurrence converts an interval count + unit to an interval-mode
// Recurrence, bounding the count so the int32 cast cannot overflow.
func intervalRecurrence(interval *int, unit *string) (Recurrence, error) {
	if interval == nil || unit == nil {
		return Recurrence{}, errors.New("interval-mode needs both interval and unit")
	}
	if *interval <= 0 || *interval > maxRecurInterval {
		return Recurrence{}, fmt.Errorf("interval must be in [1, %d]", maxRecurInterval)
	}
	u := strings.ToLower(*unit)
	if !validRecurUnit(u) {
		return Recurrence{}, fmt.Errorf("unsupported unit %q (supported: days, weeks, months, years)", *unit)
	}
	n := int32(*interval) // #nosec G115 -- bounded to [1, maxRecurInterval] above
	return Recurrence{Interval: &n, Unit: &u}, nil
}

// advanceActivate handles advance(action=activate): someday → todo. The
// SQL guard (WHERE state='someday') makes any other state surface
// ErrNotFound, reported as an invalid transition — mirroring drop's
// inbox guard.
func (h *Handler) advanceActivate(w http.ResponseWriter, r *http.Request, store *Store, id uuid.UUID) {
	item, err := store.Activate(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			api.Error(w, http.StatusBadRequest, "INVALID_TRANSITION",
				"activate requires someday state")
			return
		}
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: item})
}

// Delete handles DELETE /api/admin/commitment/todos/{id}. Only inbox
// rows are hard-deletable; non-inbox rows surface as ErrNotFound to
// push callers toward /advance/defer.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid todo id")
		return
	}
	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	if err := store.Delete(r.Context(), id); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validPriority(p string) bool {
	return p == "high" || p == "medium" || p == "low"
}

// validState reports whether s is a member of the todo_state enum.
// Validated at the handler boundary so a bad filter value is a 400, not
// a PostgreSQL cast error surfacing as 500. Covers all seven todo_state
// values including the terminal archived/dismissed states, which the admin
// backlog must be able to filter by.
func validState(s string) bool {
	switch State(s) {
	case StateInbox, StateTodo, StateInProgress, StateDone, StateSomeday, StateArchived, StateDismissed:
		return true
	default:
		return false
	}
}

func validEnergy(e string) bool {
	return e == "high" || e == "medium" || e == "low"
}

func parsePosInt(s string, defaultVal int) int {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return defaultVal
		}
		n = n*10 + int(c-'0')
		if n > 10000 {
			return defaultVal
		}
	}
	if n == 0 {
		return defaultVal
	}
	return n
}

// actorFromContext resolves the authenticated agent identity for the
// created_by stamp.
func actorFromContext(r *http.Request) string {
	if a, ok := api.ActorFromContext(r.Context()); ok {
		return a
	}
	return "human"
}
