package task

import (
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/agent/artifact"
	"github.com/Koopa0/koopa/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "task not found"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT", Message: "task conflict"},
	{Target: ErrInvalidInput, Status: http.StatusBadRequest, Code: "BAD_REQUEST", Message: "invalid input"},
	{Target: ErrCompletionOutputsMissing, Status: http.StatusConflict, Code: "COMPLETION_MISSING_OUTPUTS", Message: "completion requires a response message and artifact"},
	{Target: agent.ErrUnknownAgent, Status: http.StatusBadRequest, Code: "UNKNOWN_AGENT", Message: "unknown agent"},
	{Target: agent.ErrForbidden, Status: http.StatusForbidden, Code: "FORBIDDEN", Message: "agent lacks required capability"},
}

// Handler handles task HTTP requests for the admin workbench.
type Handler struct {
	store     *Store
	artifacts *artifact.Store
	registry  *agent.Registry
	logger    *slog.Logger
}

// NewHandler returns a task Handler.
func NewHandler(store *Store, artifacts *artifact.Store, registry *agent.Registry, logger *slog.Logger) *Handler {
	return &Handler{store: store, artifacts: artifacts, registry: registry, logger: logger}
}

// List handles GET /api/admin/tasks.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page, perPage := api.ParsePagination(r)

	var state *State
	if s := r.URL.Query().Get("state"); s != "" {
		v := State(s)
		if !validState(v) {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid state value")
			return
		}
		state = &v
	}

	tasks, total, err := h.store.TasksPaged(r.Context(), state, page, perPage)
	if err != nil {
		h.logger.Error("listing tasks", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list tasks")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(tasks, total, page, perPage))
}

// Open handles GET /api/admin/tasks/open.
func (h *Handler) Open(w http.ResponseWriter, r *http.Request) {
	page, perPage := api.ParsePagination(r)

	tasks, total, err := h.store.OpenPaged(r.Context(), page, perPage)
	if err != nil {
		h.logger.Error("listing open tasks", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list open tasks")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(tasks, total, page, perPage))
}

// Completed handles GET /api/admin/tasks/completed.
func (h *Handler) Completed(w http.ResponseWriter, r *http.Request) {
	page, perPage := api.ParsePagination(r)

	tasks, total, err := h.store.CompletedPaged(r.Context(), page, perPage)
	if err != nil {
		h.logger.Error("listing completed tasks", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list completed tasks")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(tasks, total, page, perPage))
}

// Get handles GET /api/admin/tasks/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid task id")
		return
	}

	t, err := h.store.Task(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: t})
}

// Messages handles GET /api/admin/tasks/{id}/messages.
func (h *Handler) Messages(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid task id")
		return
	}

	msgs, err := h.store.Messages(r.Context(), id)
	if err != nil {
		h.logger.Error("listing task messages", "task_id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list messages")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: msgs})
}

// Artifacts handles GET /api/admin/tasks/{id}/artifacts.
func (h *Handler) Artifacts(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid task id")
		return
	}

	arts, err := h.artifacts.ForTask(r.Context(), id)
	if err != nil {
		h.logger.Error("listing task artifacts", "task_id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list artifacts")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: arts})
}

// SubmitRequest is the POST body for creating a human-submitted task.
// Source is derived from the per-request actor ("human") — the caller
// does not send it.
type SubmitRequest struct {
	Target   string      `json:"target"`
	Title    string      `json:"title"`
	Priority *string     `json:"priority,omitempty"`
	Parts    []*a2a.Part `json:"parts"`
}

// Submit handles POST /api/admin/coordination/tasks — human-source task
// creation. Source auto-set to the per-request actor identity.
func (h *Handler) Submit(w http.ResponseWriter, r *http.Request) {
	body, err := api.Decode[SubmitRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if body.Target == "" || body.Title == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "target and title are required")
		return
	}
	if len(body.Parts) == 0 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "parts must be non-empty")
		return
	}

	source, ok := api.ActorFromContext(r.Context())
	if !ok {
		source = "human"
	}

	auth, err := agent.Authorize(r.Context(), h.registry, agent.Name(source), agent.ActionSubmitTask)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	t, err := store.Submit(r.Context(), auth, &SubmitInput{
		Source:       source,
		Target:       body.Target,
		Title:        body.Title,
		Priority:     body.Priority,
		RequestParts: body.Parts,
	})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: t})
}

// Approve handles POST /api/admin/coordination/tasks/{id}/approve.
// Tasks have no `approved` state, so approval appends a response message
// acknowledging the completion and returns the task. Approval is an
// acknowledgement event, not a state transition.
//
// No agent.Authorize call: Approve goes through task.Store.AppendMessage,
// which is the same path as Reply and carries no compile-time capability
// gate. The task state machine itself is not advanced here — any agent
// that can reach this route (JWT + adminMid) may record an approval
// message. If a future multi-agent deployment needs to restrict who can
// approve, lift this to an explicit ActionApproveTask on agent.Capability
// and put the mutation behind Authorize.
func (h *Handler) Approve(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid task id")
		return
	}
	type approveBody struct {
		Notes string `json:"notes,omitempty"`
	}
	body, err := api.Decode[approveBody](w, r)
	if err != nil && !errors.Is(err, io.EOF) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}

	notes := body.Notes
	if notes == "" {
		notes = "Approved."
	}
	if _, err := store.AppendMessage(r.Context(), id, RoleResponse, []*a2a.Part{a2a.NewTextPart(notes)}); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	t, err := store.Task(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: t})
}

// Cancel handles POST /api/admin/coordination/tasks/{id}/cancel.
// Transitions submitted/working → canceled; optional reason is recorded
// as a response message first so the audit trail keeps the explanation.
func (h *Handler) Cancel(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid task id")
		return
	}
	type cancelBody struct {
		Reason string `json:"reason,omitempty"`
	}
	body, err := api.Decode[cancelBody](w, r)
	if err != nil && !errors.Is(err, io.EOF) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}

	if body.Reason != "" {
		if _, err := store.AppendMessage(r.Context(), id, RoleResponse, []*a2a.Part{a2a.NewTextPart(body.Reason)}); err != nil {
			api.HandleError(w, h.logger, err, storeErrors...)
			return
		}
	}

	actor, ok := api.ActorFromContext(r.Context())
	if !ok {
		actor = "human"
	}
	auth, err := agent.Authorize(r.Context(), h.registry, agent.Name(actor), agent.ActionCancelTask)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	t, err := store.Cancel(r.Context(), auth, id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: t})
}

// Reply handles POST /api/admin/tasks/{id}/reply.
// Appends a human message (role=response) to the task thread.
func (h *Handler) Reply(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid task id")
		return
	}

	type replyBody struct {
		Parts []*a2a.Part `json:"parts"`
	}
	body, err := api.Decode[replyBody](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if len(body.Parts) == 0 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "parts is required and must not be empty")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	parts := body.Parts
	msg, err := store.AppendMessage(r.Context(), id, RoleResponse, parts)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: msg})
}

// RequestRevision handles POST /api/admin/tasks/{id}/request-revision.
// Optionally appends a reason message, then transitions completed → revision_requested.
func (h *Handler) RequestRevision(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid task id")
		return
	}

	// Optional reason body.
	type revisionBody struct {
		Reason string `json:"reason"`
	}
	body, err := api.Decode[revisionBody](w, r)
	if err != nil && !errors.Is(err, io.EOF) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}

	// Append reason as a response message before state transition.
	if body.Reason != "" {
		parts := []*a2a.Part{a2a.NewTextPart(body.Reason)}
		if _, err := store.AppendMessage(r.Context(), id, RoleResponse, parts); err != nil {
			api.HandleError(w, h.logger, err, storeErrors...)
			return
		}
	}

	auth, err := agent.Authorize(r.Context(), h.registry, "human", agent.ActionRequestRevision)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	t, err := store.RequestRevision(r.Context(), auth, id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: t})
}

// openTaskLimit caps the number of open tasks per agent lookup.
const openTaskLimit = 50

// AgentTasks handles GET /api/admin/agents/{name}/tasks.
// Returns open tasks where the agent is assignee or creator.
func (h *Handler) AgentTasks(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := h.registry.Get(agent.Name(name)); err != nil {
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "agent not found")
		return
	}

	assigned, err := h.store.OpenForAssignee(r.Context(), name, openTaskLimit)
	if err != nil {
		h.logger.Error("listing tasks for assignee", "agent", name, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list agent tasks")
		return
	}

	created, err := h.store.OpenForCreator(r.Context(), name, openTaskLimit)
	if err != nil {
		h.logger.Error("listing tasks for creator", "agent", name, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list agent tasks")
		return
	}

	// Merge and deduplicate by ID.
	seen := make(map[string]bool, len(assigned))
	result := make([]Task, 0, len(assigned)+len(created))
	for i := range assigned {
		seen[assigned[i].ID.String()] = true
		result = append(result, assigned[i])
	}
	for i := range created {
		if !seen[created[i].ID.String()] {
			result = append(result, created[i])
		}
	}

	api.Encode(w, http.StatusOK, api.Response{Data: result})
}

func validState(s State) bool {
	switch s {
	case StateSubmitted, StateWorking, StateCompleted, StateCanceled, StateRevisionRequested:
		return true
	}
	return false
}
