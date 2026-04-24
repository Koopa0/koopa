// handler.go holds the admin HTTP handlers for personal GTD todos.
// Every mutation route runs under adminMid in cmd/app/routes.go so the
// per-request tx in context carries koopa.actor and the audit trigger
// records the real mutator.
//
// State transitions go through POST {id}/advance (clarify, start,
// complete, defer, drop) instead of riding PUT so every state change
// surfaces as a distinct audit event. PUT mutates scalar fields only —
// state transitions via PUT return 400.

package todo

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
)

// storeErrors maps todo sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "todo not found"},
}

// ErrInvalidTransition is returned by Advance when the caller supplies
// an unknown action. Defined at the handler to avoid leaking HTTP
// vocabulary into the store.
var ErrInvalidTransition = errors.New("todo: invalid transition")

// Handler handles admin HTTP requests for todos.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a todo Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
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
// Query params: state, project (uuid), priority, energy, q, limit,
// due_before (YYYY-MM-DD). due_before is applied in Go after the SQL
// query returns.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	project := q.Get("project")
	priority := q.Get("priority")
	energy := q.Get("energy")
	search := q.Get("q")
	limit := 100
	if v := q.Get("per_page"); v != "" {
		if n := parsePosInt(v, 100); n > 0 && n <= 200 {
			limit = n
		}
	}

	rows, err := h.store.BacklogItems(r.Context(), state, project, energy, priority, search, limit)
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
				CreatedAt:     r.CreatedAt,
				UpdatedAt:     r.UpdatedAt,
			},
			ProjectTitle: r.ProjectTitle,
		}
	}
	api.Encode(w, http.StatusOK, api.Response{Data: out})
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
		h.logger.Error("creating todo", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to create todo")
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

// advanceRequest mirrors the MCP advance_work action set. 'drop' removes
// the row — see storeDelete comment.
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
		actionErr = store.Complete(r.Context(), id, nil)
	case "defer":
		actionErr = store.Defer(r.Context(), id)
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
			"action must be one of: clarify, start, complete, defer, drop")
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
