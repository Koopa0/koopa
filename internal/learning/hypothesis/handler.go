package hypothesis

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses.
//
// ErrEvidenceRequired surfaces when validation was bypassed and the
// schema CHECK fires; 422 matches the inline validation response so
// clients see a consistent contract. ErrEvidenceNotFound is a 400
// because the caller-supplied UUID was well-formed but refers to a
// row that does not exist. ErrInvalidTransition is a 422 — it means
// the state the caller asked for cannot be reached via the method
// they chose (e.g. UpdateState called with verified/invalidated, or
// chk_hypothesis_resolved_at fired) — a client input problem, not an
// internal server fault.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "hypothesis not found"},
	{Target: ErrEvidenceRequired, Status: http.StatusUnprocessableEntity, Code: "EVIDENCE_REQUIRED", Message: "at least one evidence source required to resolve"},
	{Target: ErrEvidenceNotFound, Status: http.StatusBadRequest, Code: "EVIDENCE_NOT_FOUND", Message: "referenced attempt or observation not found"},
	{Target: ErrInvalidTransition, Status: http.StatusUnprocessableEntity, Code: "INVALID_TRANSITION", Message: "invalid state transition"},
}

// Handler handles hypothesis HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a hypothesis Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// List handles GET /api/admin/hypotheses.
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

	records, total, err := h.store.RecordsPaged(r.Context(), state, page, perPage)
	if err != nil {
		h.logger.Error("listing hypotheses", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list hypotheses")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(records, total, page, perPage))
}

// Get handles GET /api/admin/hypotheses/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid hypothesis id")
		return
	}

	rec, err := h.store.RecordByID(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: rec})
}

// LineageResponse is the wire shape for /hypotheses/:id/lineage.
// The origin and linked arrays derive from the hypothesis metadata's
// evidence arrays and the resolved_by_* columns; a richer session +
// attempts walk-back is deferred until the frontend consumes the
// minimal shape.
type LineageResponse struct {
	Hypothesis   *Record `json:"hypothesis"`
	Origin       any     `json:"origin"`
	Observations []any   `json:"observations"`
	EvidenceLog  []any   `json:"evidence_log"`
}

// Lineage handles GET /api/admin/learning/hypotheses/{id}/lineage.
// Returns the Record plus empty origin / observation / evidence arrays —
// the consumer walks the resolved_by_attempt_id FK itself when it needs
// the originating session chain.
func (h *Handler) Lineage(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid hypothesis id")
		return
	}
	rec, err := h.store.RecordByID(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	resp := LineageResponse{
		Hypothesis:   rec,
		Origin:       map[string]any{},
		Observations: []any{},
		EvidenceLog:  []any{},
	}
	api.Encode(w, http.StatusOK, api.Response{Data: resp})
}

// resolveRequest is the body for POST /verify and /invalidate. All fields
// are optional at the type level; the handler enforces that at least
// one carries a usable value.
type resolveRequest struct {
	ResolvedByAttemptID     *string `json:"resolved_by_attempt_id,omitempty"`
	ResolvedByObservationID *string `json:"resolved_by_observation_id,omitempty"`
	ResolutionSummary       *string `json:"resolution_summary,omitempty"`
}

// Verify handles POST /api/admin/hypotheses/{id}/verify.
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	h.resolve(w, r, StateVerified)
}

// Invalidate handles POST /api/admin/hypotheses/{id}/invalidate.
func (h *Handler) Invalidate(w http.ResponseWriter, r *http.Request) {
	h.resolve(w, r, StateInvalidated)
}

// Archive handles POST /api/admin/hypotheses/{id}/archive. Archive does
// not require evidence and stays on the legacy UpdateState path.
func (h *Handler) Archive(w http.ResponseWriter, r *http.Request) {
	h.transitionState(w, r, StateArchived)
}

// resolve decodes the request body, validates the evidence contract, and
// routes a transition to verified or invalidated through UpdateResolution.
//
// Validation ordering matters: UUIDs are parsed BEFORE checking for
// "at least one evidence source" so a malformed UUID returns 400 even
// if the caller also supplied a summary. This keeps client errors
// loud instead of silently succeeding with a partial payload.
func (h *Handler) resolve(w http.ResponseWriter, r *http.Request, target State) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid hypothesis id")
		return
	}

	params, ok := parseResolveRequest(w, r)
	if !ok {
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	rec, err := store.UpdateResolution(r.Context(), id, target, params)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: rec})
}

// parseResolveRequest decodes and validates a resolve request body via
// the shared ValidateResolveInput helper. On any validation failure it
// writes the error response and returns ok=false; callers MUST return
// immediately in that case.
//
// Empty body is allowed on decode (all fields optional at JSON level) so
// an entirely missing body produces an EVIDENCE_REQUIRED response, not a
// malformed-JSON 400. A whitespace-only summary is treated as "no summary"
// to match the DB CHECK (btrim(resolution_summary) <> ”).
func parseResolveRequest(w http.ResponseWriter, r *http.Request) (ResolveParams, bool) {
	body, decErr := api.Decode[resolveRequest](w, r)
	if decErr != nil && !errors.Is(decErr, io.EOF) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return ResolveParams{}, false
	}

	params, err := ValidateResolveInput(body.ResolvedByAttemptID, body.ResolvedByObservationID, body.ResolutionSummary)
	if err != nil {
		if fieldErr, ok := errors.AsType[*InvalidEvidenceIDError](err); ok {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid "+fieldErr.Field)
			return ResolveParams{}, false
		}
		switch {
		case errors.Is(err, ErrResolutionSummaryTooLong):
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "resolution_summary too large")
		case errors.Is(err, ErrResolutionSummaryInvalid):
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "resolution_summary contains control characters")
		case errors.Is(err, ErrEvidenceRequired):
			api.Error(w, http.StatusUnprocessableEntity, "EVIDENCE_REQUIRED",
				"at least one of resolved_by_attempt_id, resolved_by_observation_id, or resolution_summary is required")
		default:
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		}
		return ResolveParams{}, false
	}
	return params, true
}

// transitionState performs a state-only update for transitions that do
// not require resolution evidence (currently: archive).
func (h *Handler) transitionState(w http.ResponseWriter, r *http.Request, target State) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid hypothesis id")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}
	rec, err := store.UpdateState(r.Context(), id, target)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: rec})
}

// maxEvidenceSize caps a single evidence entry's JSON payload at 32 KB.
// The cap applies to the per-request entry, not the accumulated
// metadata blob — the SQL path appends atomically so there is no
// handler-side aggregate to measure without a redundant round trip.
const maxEvidenceSize = 32 * 1024

// AddEvidence handles POST /api/admin/hypotheses/{id}/evidence.
//
// Appends a single evidence entry to metadata->{supporting,counter}_evidence
// via a single UPDATE (Store.AppendEvidence). The previous implementation
// read the row, mutated the in-memory metadata map, and wrote it back;
// under Read Committed with no row lock, two concurrent evidence posts
// could race and silently drop one entry. The SQL path closes that gap
// by letting PostgreSQL serialize the append at the row level.
func (h *Handler) AddEvidence(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid hypothesis id")
		return
	}

	// Spec: { "evidence": { "type": "supporting", "description": "...", ... } }
	// The evidence object is arbitrary JSON; "type" inside determines the array.
	type evidenceBody struct {
		Evidence map[string]any `json:"evidence"`
	}
	body, decErr := api.Decode[evidenceBody](w, r)
	if decErr != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if body.Evidence == nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "evidence is required")
		return
	}
	evidenceType, _ := body.Evidence["type"].(string)
	if evidenceType != "supporting" && evidenceType != "counter" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "evidence.type must be supporting or counter")
		return
	}

	entryJSON, err := json.Marshal(body.Evidence)
	if err != nil {
		h.logger.Error("marshalling evidence entry", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to marshal evidence")
		return
	}
	if len(entryJSON) > maxEvidenceSize {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "evidence too large")
		return
	}

	store := h.store
	if tx, ok := api.TxFromContext(r.Context()); ok {
		store = h.store.WithTx(tx)
	}

	updated, err := store.AppendEvidence(r.Context(), id, evidenceType, entryJSON)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: updated})
}

func validState(s State) bool {
	switch s {
	case StateUnverified, StateVerified, StateInvalidated, StateArchived:
		return true
	}
	return false
}
