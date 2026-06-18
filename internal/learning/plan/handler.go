// Copyright 2026 Koopa. All rights reserved.

// handler.go holds the admin HTTP handlers for learning plans.
//
// Plan / entry lifecycle decisions stay centralized in the Store — the
// HTTP handler is a thin adapter. Completed entries MUST carry
// completed_by_attempt_id + reason per mcp-decision-policy §13; the
// handler rejects completion requests missing those fields.

package plan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa/internal/api"
)

// storeErrors maps plan sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "plan or entry not found"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT", Message: "plan conflict"},
}

// Handler handles admin HTTP requests for learning plans.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a plan Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

func (h *Handler) mustAdminTx(w http.ResponseWriter, r *http.Request) (*Store, bool) {
	tx, ok := api.TxFromContext(r.Context())
	if !ok {
		h.logger.Error("plan mutation without tx",
			"event", "middleware_not_wired",
			"method", r.Method, "path", r.URL.Path)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
		return nil, false
	}
	return h.store.WithTx(tx), true
}

// List handles GET /api/admin/learning/plans. Rows carry entry_total /
// entry_done counts for the admin list's Entries/Progress columns.
// Query params: domain (filter), status (filter).
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domain := q.Get("domain")
	if domain != "" {
		var status *string
		if v := q.Get("status"); v != "" {
			status = &v
		}
		plans, err := h.store.PlansByDomain(r.Context(), domain, status)
		if err != nil {
			h.logger.Error("listing plans by domain", "error", err)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list plans")
			return
		}
		if plans == nil {
			plans = []Summary{}
		}
		api.Encode(w, http.StatusOK, api.Response{Data: plans})
		return
	}

	plans, err := h.store.PlansInManagement(r.Context())
	if err != nil {
		h.logger.Error("listing plans in management", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list plans")
		return
	}
	if plans == nil {
		plans = []Summary{}
	}
	api.Encode(w, http.StatusOK, api.Response{Data: plans})
}

// DetailResponse is the wire shape for /plans/:id — plan + goal name +
// entries + progress. GoalName is the linked goal's title for the meta
// strip, empty string when the plan has no goal.
type DetailResponse struct {
	Plan     *Plan         `json:"plan"`
	GoalName string        `json:"goal_name"`
	Entries  []EntryDetail `json:"entries"`
	Progress *Progress     `json:"progress"`
}

// Detail handles GET /api/admin/learning/plans/{id}.
func (h *Handler) Detail(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid plan id")
		return
	}
	plan, err := h.store.Plan(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: h.detail(r.Context(), h.store, plan)})
}

// detail assembles the plan + goal name + entries + progress envelope from
// the given store. Goal-name, entries, and progress failures degrade to a
// partial envelope — the plan row is authoritative and the caller still
// gets a usable response. Mutation handlers pass their tx-bound store so
// the envelope reflects writes made earlier in the same request.
func (h *Handler) detail(ctx context.Context, store *Store, p *Plan) DetailResponse {
	resp := DetailResponse{Plan: p, Entries: []EntryDetail{}}
	if name, err := store.GoalName(ctx, p.ID); err == nil {
		resp.GoalName = name
	} else {
		h.logger.Warn("plan detail: goal name fetch failed", "plan_id", p.ID, "error", err)
	}
	if entries, err := store.EntriesDetailed(ctx, p.ID); err == nil {
		resp.Entries = entries
	} else {
		h.logger.Warn("plan detail: entries fetch failed", "plan_id", p.ID, "error", err)
	}
	if prog, err := store.Progress(ctx, p.ID); err == nil {
		resp.Progress = prog
	} else {
		h.logger.Warn("plan detail: progress fetch failed", "plan_id", p.ID, "error", err)
	}
	return resp
}

// CreateRequest is the JSON body for POST /api/admin/learning/plans — the
// owner decision-stamp that replaces the removed propose_learning_plan /
// commit MCP flow. The plan is created in status=draft (the store enforces
// this); activation goes through the manage_plan(update_plan) path. domain
// and title are required. created_by is taken from the request actor, not
// the body.
type CreateRequest struct {
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Domain      string          `json:"domain"`
	GoalID      *uuid.UUID      `json:"goal_id,omitempty"`
	TargetCount *int32          `json:"target_count,omitempty"`
	PlanConfig  json.RawMessage `json:"plan_config,omitempty"`
}

// Create handles POST /api/admin/learning/plans.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[CreateRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Title == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title is required")
		return
	}
	if req.Domain == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "domain is required")
		return
	}
	if containsControlChars(req.Title) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title must not contain control characters")
		return
	}
	if containsControlChars(req.Description) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "description must not contain control characters")
		return
	}
	if containsControlChars(req.Domain) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "domain must not contain control characters")
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	plan, err := store.CreatePlan(r.Context(), &CreatePlanParams{
		Title:       req.Title,
		Description: req.Description,
		Domain:      req.Domain,
		GoalID:      req.GoalID,
		TargetCount: req.TargetCount,
		PlanConfig:  req.PlanConfig,
		CreatedBy:   actorFromContext(r),
	})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: plan})
}

// actorFromContext resolves the authenticated agent identity for the
// created_by stamp, falling back to "human" for the admin write convention.
func actorFromContext(r *http.Request) string {
	if a, ok := api.ActorFromContext(r.Context()); ok {
		return a
	}
	return "human"
}

// AddEntriesRequest is the POST body for adding entries to a plan.
// Entries are appended in the given order; position is auto-assigned.
type AddEntriesRequest struct {
	Entries []NewEntry `json:"entries"`
}

// NewEntry holds the fields required to add a single entry. phase is
// optional; when provided it must pass ValidatePhase.
type NewEntry struct {
	LearningTargetID uuid.UUID `json:"learning_target_id"`
	Phase            *string   `json:"phase,omitempty"`
}

// AddEntries handles POST /api/admin/learning/plans/{id}/entries.
func (h *Handler) AddEntries(w http.ResponseWriter, r *http.Request) {
	planID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid plan id")
		return
	}
	req, err := api.Decode[AddEntriesRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if len(req.Entries) == 0 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "entries must be non-empty")
		return
	}
	if len(req.Entries) > maxEntriesPerRequest {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "entries exceeds maximum per request")
		return
	}
	for i := range req.Entries {
		if req.Entries[i].Phase != nil {
			if err := ValidatePhase(*req.Entries[i].Phase); err != nil {
				api.Error(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
				return
			}
		}
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}

	// Resolve starting position: append after the current max position.
	existing, err := store.Entries(r.Context(), planID)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	if len(existing) > math.MaxInt32-len(req.Entries) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "plan already has too many entries")
		return
	}
	nextPosition := int32(len(existing) + 1) // #nosec G115 -- bounded above

	out := make([]Entry, 0, len(req.Entries))
	for i, ne := range req.Entries {
		entry, err := store.AddEntry(r.Context(), AddEntryParams{
			PlanID:           planID,
			LearningTargetID: ne.LearningTargetID,
			Position:         nextPosition + int32(i), // #nosec G115 -- bounded by request size
			Phase:            ne.Phase,
		})
		if err != nil {
			api.HandleError(w, h.logger, err, storeErrors...)
			return
		}
		out = append(out, *entry)
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: out})
}

// UpdateEntryRequest is the PUT body for updating an entry.
// Completion (status=completed) is policy-gated — the client MUST
// include completed_by_attempt_id and a non-empty reason (mcp-decision-
// policy §13). The handler rejects completion requests missing either.
type UpdateEntryRequest struct {
	Status               EntryStatus `json:"status"`
	Reason               *string     `json:"reason,omitempty"`
	CompletedByAttemptID *uuid.UUID  `json:"completed_by_attempt_id,omitempty"`
	SubstitutedBy        *uuid.UUID  `json:"substituted_by,omitempty"`
}

// UpdateEntry handles PUT /api/admin/learning/plans/{id}/entries/{entry_id}.
func (h *Handler) UpdateEntry(w http.ResponseWriter, r *http.Request) {
	entryID, err := uuid.Parse(r.PathValue("entry_id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid entry id")
		return
	}
	req, err := api.Decode[UpdateEntryRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Status == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "status is required")
		return
	}

	// Completion policy gate.
	if req.Status == EntryCompleted {
		if req.CompletedByAttemptID == nil {
			api.Error(w, http.StatusBadRequest, "AUDIT_REQUIRED",
				"completed_by_attempt_id is required when marking an entry completed")
			return
		}
		if req.Reason == nil || *req.Reason == "" {
			api.Error(w, http.StatusBadRequest, "AUDIT_REQUIRED",
				"reason is required when marking an entry completed")
			return
		}
	}
	if req.Status == EntrySubstituted && req.SubstitutedBy == nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST",
			"substituted_by is required for substituted status")
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}

	params := UpdateEntryStatusParams{
		ID:                   entryID,
		Status:               req.Status,
		Reason:               req.Reason,
		CompletedByAttemptID: req.CompletedByAttemptID,
		SubstitutedBy:        req.SubstitutedBy,
	}
	if req.Status == EntryCompleted {
		now := time.Now().UTC()
		params.CompletedAt = &now
	}

	entry, err := store.UpdateEntryStatus(r.Context(), params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "entry not found")
			return
		}
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: entry})
}

// UpdateStatusRequest is the PUT body for updating a plan's lifecycle status.
type UpdateStatusRequest struct {
	Status Status `json:"status"`
}

// UpdateStatus handles PUT /api/admin/learning/plans/{id}/status.
// The status value is validated against the plan lifecycle enum at the
// handler so an unknown value returns 400 instead of tripping the
// database CHECK constraint. Returns the updated plan.
func (h *Handler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid plan id")
		return
	}
	req, err := api.Decode[UpdateStatusRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Status == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "status is required")
		return
	}
	if !validStatus(req.Status) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST",
			"status must be one of: draft, active, paused, completed, abandoned")
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	updated, err := store.UpdatePlanStatus(r.Context(), id, req.Status)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: updated})
}

// ReorderRequest is the PUT body for reordering a plan's entries. Every
// referenced entry must belong to the plan; requested positions must be
// unique and must not collide with the positions of entries left out of
// the request.
type ReorderRequest struct {
	Entries []reorderEntryRequest `json:"entries"`
}

// reorderEntryRequest is the wire shape of one reorder item. The JSON field
// is plan_entry_id (the identifier the admin UI passes back); it maps onto
// the store's ReorderEntry.EntryID before the position write.
type reorderEntryRequest struct {
	PlanEntryID uuid.UUID `json:"plan_entry_id"`
	Position    int32     `json:"position"`
}

// validateReorderEntries checks the request-shape rules — non-nil ids,
// non-negative positions, no duplicate ids, no duplicate positions — and
// maps the request items onto the store's ReorderEntry type. The error
// message is client-facing (400). Plan-membership and untouched-position
// collision are enforced inside Store.Reorder.
func validateReorderEntries(entries []reorderEntryRequest) ([]ReorderEntry, error) {
	ids := make(map[uuid.UUID]struct{}, len(entries))
	positions := make(map[int32]struct{}, len(entries))
	out := make([]ReorderEntry, len(entries))
	for i, e := range entries {
		if e.PlanEntryID == uuid.Nil {
			return nil, fmt.Errorf("entries[%d]: plan_entry_id is required", i)
		}
		if e.Position < 0 {
			return nil, fmt.Errorf("entries[%d]: position must be >= 0", i)
		}
		if _, dup := ids[e.PlanEntryID]; dup {
			return nil, fmt.Errorf("entries[%d]: duplicate plan_entry_id %s", i, e.PlanEntryID)
		}
		if _, dup := positions[e.Position]; dup {
			return nil, fmt.Errorf("entries[%d]: duplicate position %d", i, e.Position)
		}
		ids[e.PlanEntryID] = struct{}{}
		positions[e.Position] = struct{}{}
		out[i] = ReorderEntry{EntryID: e.PlanEntryID, Position: e.Position}
	}
	return out, nil
}

// Reorder handles PUT /api/admin/learning/plans/{id}/reorder.
//
// All position updates apply atomically inside the request transaction —
// either every entry lands on its new position or none do (the middleware
// rolls the tx back on any non-2xx response). Positions must be >= 0, the
// same floor AddEntries enforces. Membership and untouched-position collision
// are enforced by Store.Reorder (ErrNotFound → 404, ErrConflict → 409).
// Returns the full plan detail envelope reflecting the new order.
func (h *Handler) Reorder(w http.ResponseWriter, r *http.Request) {
	planID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid plan id")
		return
	}
	req, err := api.Decode[ReorderRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if len(req.Entries) == 0 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "entries must be non-empty")
		return
	}
	entries, err := validateReorderEntries(req.Entries)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	p, err := store.Plan(r.Context(), planID)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	if err := store.Reorder(r.Context(), planID, entries); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: h.detail(r.Context(), store, p)})
}

// RemoveEntry handles DELETE /api/admin/learning/plans/{id}/entries/{entry_id}.
//
// Removal is restricted to draft plans — once a plan is active its entries
// carry execution history, so dropping one goes through the skip or
// substitute transitions instead of deletion. Positions of the remaining
// entries are left untouched; gaps are acceptable and the reorder endpoint
// renumbers when needed. Returns 204 on success.
func (h *Handler) RemoveEntry(w http.ResponseWriter, r *http.Request) {
	planID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid plan id")
		return
	}
	entryID, err := uuid.Parse(r.PathValue("entry_id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid entry id")
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	p, err := store.Plan(r.Context(), planID)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	if p.Status != StatusDraft {
		api.Error(w, http.StatusConflict, "CONFLICT",
			"entries can only be removed from draft plans (use skip or substitute on active plans)")
		return
	}
	entry, err := store.Entry(r.Context(), entryID)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	if entry.PlanID != planID {
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "entry does not belong to this plan")
		return
	}
	if err := store.RemoveEntries(r.Context(), planID, []uuid.UUID{entryID}); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
