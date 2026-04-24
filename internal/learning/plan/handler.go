// handler.go holds the admin HTTP handlers for learning plans.
//
// Plan / entry lifecycle decisions stay centralized in the Store — the
// HTTP handler is a thin adapter. Completed entries MUST carry
// completed_by_attempt_id + reason per mcp-decision-policy §13; the
// handler rejects completion requests missing those fields.

package plan

import (
	"errors"
	"log/slog"
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

// List handles GET /api/admin/learning/plans.
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
			plans = []Plan{}
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
		plans = []Plan{}
	}
	api.Encode(w, http.StatusOK, api.Response{Data: plans})
}

// DetailResponse is the wire shape for /plans/:id — plan + entries + progress.
type DetailResponse struct {
	*Plan
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
	resp := DetailResponse{Plan: plan, Entries: []EntryDetail{}}
	if entries, eerr := h.store.EntriesDetailed(r.Context(), id); eerr == nil {
		resp.Entries = entries
	} else {
		h.logger.Warn("plan detail: entries fetch failed", "plan_id", id, "error", eerr)
	}
	if prog, err := h.store.Progress(r.Context(), id); err == nil {
		resp.Progress = prog
	} else {
		h.logger.Warn("plan detail: progress fetch failed", "plan_id", id, "error", err)
	}
	api.Encode(w, http.StatusOK, api.Response{Data: resp})
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
	if len(existing) > int(^int32(0))-len(req.Entries) {
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
