// handler.go holds the admin HTTP handlers for the Zettelkasten note
// surface. All mutation routes are wired through adminMid in
// cmd/app/routes.go, so the per-request tx in context carries
// koopa.actor and audit triggers record the real mutator.
//
// Maturity transitions go through their own handler (Maturity) rather
// than via Update, matching the Store split: UpdateNote mutates
// editable fields, UpdateNoteMaturity is a separate, auditable
// transition.

package note

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "note not found"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT", Message: "note slug conflict"},
	{Target: ErrInvalidKind, Status: http.StatusBadRequest, Code: "INVALID_KIND", Message: "invalid note kind"},
	{Target: ErrInvalidMaturity, Status: http.StatusBadRequest, Code: "INVALID_MATURITY", Message: "invalid note maturity"},
}

// Handler handles note HTTP requests. The public surface is empty — notes
// are Koopa-private artifacts — so every handler requires JWT + adminMid.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a note Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// mustAdminTx extracts the request-scoped pgx.Tx supplied by
// api.ActorMiddleware. Admin mutation paths require a tx so audit
// triggers attribute writes to the real actor.
func (h *Handler) mustAdminTx(w http.ResponseWriter, r *http.Request) (store *Store, ok bool) {
	tx, ok := api.TxFromContext(r.Context())
	if !ok {
		h.logger.Error("note admin mutation without tx",
			"event", "middleware_not_wired",
			"method", r.Method, "path", r.URL.Path)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
		return nil, false
	}
	return h.store.WithTx(tx), true
}

// response is the wire shape of a note. Extends the stored fields with
// resolved concept / target refs so the admin editor does not need a
// second round-trip for display data.
type response struct {
	*Note
	Concepts []ConceptRef `json:"concepts"`
	Targets  []TargetRef  `json:"targets"`
}

// List handles GET /api/admin/knowledge/notes.
// Query params: page, per_page, kind (single), maturity (single).
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page, perPage := api.ParsePagination(r)
	f := Filter{Page: page, PerPage: perPage}

	if v := r.URL.Query().Get("kind"); v != "" {
		k := Kind(v)
		if !k.Valid() {
			api.Error(w, http.StatusBadRequest, "INVALID_KIND", "invalid note kind")
			return
		}
		f.Kind = &k
	}
	if v := r.URL.Query().Get("maturity"); v != "" {
		m := Maturity(v)
		if !m.Valid() {
			api.Error(w, http.StatusBadRequest, "INVALID_MATURITY", "invalid note maturity")
			return
		}
		f.Maturity = &m
	}

	notes, total, err := h.store.Notes(r.Context(), f)
	if err != nil {
		h.logger.Error("listing notes", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list notes")
		return
	}

	// Strip body from list responses — list is for browsing, callers hit
	// Get for the full body. Concepts / targets stay for UI badges.
	out := make([]response, len(notes))
	for i := range notes {
		n := notes[i]
		n.Body = ""
		out[i] = h.enrich(r, &n)
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(out, total, f.Page, f.PerPage))
}

// Get handles GET /api/admin/knowledge/notes/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid note id")
		return
	}
	n, err := h.store.Note(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: h.enrich(r, n)})
}

// createRequest is the POST body for Create. created_by is not caller-
// supplied — the middleware actor fills it.
type createRequest struct {
	Slug         string         `json:"slug"`
	Title        string         `json:"title"`
	Body         string         `json:"body"`
	Kind         Kind           `json:"kind"`
	Maturity     Maturity       `json:"maturity,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	ConceptSlugs []string       `json:"concept_slugs,omitempty"`
	TargetIDs    []uuid.UUID    `json:"target_ids,omitempty"`
}

// Create handles POST /api/admin/knowledge/notes.
// concept_slugs / target_ids are accepted for parity with the MCP
// create_note shape. The HTTP path does not resolve them into junction
// rows; callers attach them through the dedicated attach endpoints.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[createRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if strings.TrimSpace(req.Title) == "" || strings.TrimSpace(req.Slug) == "" || req.Kind == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug, title, and kind are required")
		return
	}
	if !req.Kind.Valid() {
		api.Error(w, http.StatusBadRequest, "INVALID_KIND", "invalid note kind")
		return
	}
	if req.Maturity != "" && !req.Maturity.Valid() {
		api.Error(w, http.StatusBadRequest, "INVALID_MATURITY", "invalid note maturity")
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	actor := actorFromContext(r)
	p := &CreateParams{
		Slug:      req.Slug,
		Title:     req.Title,
		Body:      req.Body,
		Kind:      req.Kind,
		Maturity:  req.Maturity,
		CreatedBy: actor,
		Metadata:  req.Metadata,
	}
	n, err := store.Create(r.Context(), p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: h.enrich(r, n)})
}

// updateRequest is the PUT body for Update. Structurally identical to
// UpdateParams so the handler can convert with a type cast; maturity is
// intentionally absent — use the maturity-specific endpoint.
type updateRequest UpdateParams

// Update handles PUT /api/admin/knowledge/notes/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid note id")
		return
	}
	req, err := api.Decode[updateRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Kind != nil && !req.Kind.Valid() {
		api.Error(w, http.StatusBadRequest, "INVALID_KIND", "invalid note kind")
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	n, err := store.Update(r.Context(), id, UpdateParams(req))
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: h.enrich(r, n)})
}

// Maturity handles POST /api/admin/knowledge/notes/{id}/maturity.
// Separate from Update so every maturity transition is an auditable
// event distinct from body / title edits.
func (h *Handler) Maturity(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid note id")
		return
	}
	type maturityBody struct {
		Maturity Maturity `json:"maturity"`
	}
	body, err := api.Decode[maturityBody](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if !body.Maturity.Valid() {
		api.Error(w, http.StatusBadRequest, "INVALID_MATURITY", "invalid note maturity")
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	n, err := store.UpdateMaturity(r.Context(), id, body.Maturity)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: h.enrich(r, n)})
}

// Delete handles DELETE /api/admin/knowledge/notes/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid note id")
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

// enrich attaches concept / target refs to a Note before wire encoding.
// Failures on either side do not fail the whole request — the UI just
// renders empty badges — but they are logged for follow-up.
func (h *Handler) enrich(r *http.Request, n *Note) response {
	out := response{Note: n, Concepts: []ConceptRef{}, Targets: []TargetRef{}}
	if n == nil {
		return out
	}
	ctx := r.Context()
	if refs, err := h.store.ConceptRefsForNote(ctx, n.ID); err != nil {
		h.logger.Warn("note enrich: loading concepts failed", "note_id", n.ID, "error", err)
	} else {
		out.Concepts = refs
	}
	if refs, err := h.store.TargetRefsForNote(ctx, n.ID); err != nil {
		h.logger.Warn("note enrich: loading targets failed", "note_id", n.ID, "error", err)
	} else {
		out.Targets = refs
	}
	return out
}

// actorFromContext resolves the authenticated agent identity for a
// created_by stamp. Mirrors the bookmark package helper.
func actorFromContext(r *http.Request) string {
	if a, ok := api.ActorFromContext(r.Context()); ok {
		return a
	}
	return "human"
}
