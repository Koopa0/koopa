// Copyright 2026 Koopa. All rights reserved.

// handler.go holds the admin HTTP handlers for the reading shelf and its
// diary. Every route lives under /api/admin/knowledge/readings — there is
// no public and no MCP surface for this domain (privacy boundary, see the
// package comment). Mutation routes are wired through adminMid in
// cmd/app/routes.go, so handlers route writes through the per-request tx
// even though no audit triggers fire on these tables.
//
// Dates cross the wire as YYYY-MM-DD strings (started_on, finished_on,
// entry_date) — they are DATE columns, not timestamps.

package reading

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "reading or reflection not found"},
	{Target: ErrInvalidInput, Status: http.StatusBadRequest, Code: "INVALID_INPUT", Message: "invalid reading input"},
}

// Handler handles reading HTTP requests. The surface is admin-only:
// reads behind authMid, mutations behind adminMid.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a reading Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// mustAdminTx extracts the request-scoped pgx.Tx supplied by
// api.ActorMiddleware so mutations stay inside the per-request tx.
func (h *Handler) mustAdminTx(w http.ResponseWriter, r *http.Request) (store *Store, ok bool) {
	tx, ok := api.TxFromContext(r.Context())
	if !ok {
		h.logger.Error("reading admin mutation without tx",
			"event", "middleware_not_wired",
			"method", r.Method, "path", r.URL.Path)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
		return nil, false
	}
	return h.store.WithTx(tx), true
}

// readingResponse is the wire shape of a reading. DATE fields are
// YYYY-MM-DD strings, null when unset.
type readingResponse struct {
	ID         uuid.UUID `json:"id"`
	Title      string    `json:"title"`
	Author     string    `json:"author"`
	Status     Status    `json:"status"`
	StartedOn  *string   `json:"started_on"`
	FinishedOn *string   `json:"finished_on"`
	IsPublic   bool      `json:"is_public"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// reflectionResponse is the wire shape of a diary entry.
type reflectionResponse struct {
	ID        uuid.UUID `json:"id"`
	ReadingID uuid.UUID `json:"reading_id"`
	EntryDate string    `json:"entry_date"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// readingDetail is the book page: the reading plus its diary thread in
// entry_date order (created_at tiebreak).
type readingDetail struct {
	readingResponse
	Reflections []reflectionResponse `json:"reflections"`
}

// List handles GET /api/admin/knowledge/readings.
// Query params: status (single, optional). Ordered by updated_at
// descending — status-group ordering for the shelf is the frontend's call.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	var filter *Status
	if v := r.URL.Query().Get("status"); v != "" {
		s := Status(v)
		if !s.Valid() {
			api.Error(w, http.StatusBadRequest, "INVALID_STATUS", "invalid reading status")
			return
		}
		filter = &s
	}
	readings, err := h.store.Readings(r.Context(), filter)
	if err != nil {
		h.logger.Error("listing readings", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list readings")
		return
	}
	out := make([]readingResponse, len(readings))
	for i := range readings {
		out[i] = toReadingResponse(&readings[i])
	}
	api.Encode(w, http.StatusOK, api.Response{Data: out})
}

// Get handles GET /api/admin/knowledge/readings/{id} — the reading plus
// its full reflection thread.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid reading id")
		return
	}
	rd, err := h.store.Reading(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	refs, err := h.store.Reflections(r.Context(), id)
	if err != nil {
		h.logger.Error("listing reflections", "reading_id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to load reflections")
		return
	}
	detail := readingDetail{
		readingResponse: toReadingResponse(rd),
		Reflections:     make([]reflectionResponse, len(refs)),
	}
	for i := range refs {
		detail.Reflections[i] = toReflectionResponse(&refs[i])
	}
	api.Encode(w, http.StatusOK, api.Response{Data: detail})
}

// createRequest is the POST body for Create. finished_on is deliberately
// absent — a finish date is recorded via Update, where the finished
// auto-stamp rule lives.
type createRequest struct {
	Title     string  `json:"title"`
	Author    string  `json:"author,omitempty"`
	Status    Status  `json:"status,omitempty"`
	StartedOn *string `json:"started_on,omitempty"`
}

// Create handles POST /api/admin/knowledge/readings.
// Status defaults to want_to_read when omitted.
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
	if containsControlChars(req.Title) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title must not contain control characters")
		return
	}
	if containsControlChars(req.Author) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "author must not contain control characters")
		return
	}
	if req.Status != "" && !req.Status.Valid() {
		api.Error(w, http.StatusBadRequest, "INVALID_STATUS", "invalid reading status")
		return
	}
	startedOn, ok := parseDate(w, req.StartedOn, "started_on")
	if !ok {
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	rd, err := store.Create(r.Context(), &CreateParams{
		Title:     req.Title,
		Author:    req.Author,
		Status:    req.Status,
		StartedOn: startedOn,
	})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: toReadingResponse(rd)})
}

// updateRequest is the PUT body for Update. All fields optional; omitted
// fields stay unchanged.
type updateRequest struct {
	Title      *string `json:"title,omitempty"`
	Author     *string `json:"author,omitempty"`
	Status     *Status `json:"status,omitempty"`
	StartedOn  *string `json:"started_on,omitempty"`
	FinishedOn *string `json:"finished_on,omitempty"`
	IsPublic   *bool   `json:"is_public,omitempty"`
}

// Update handles PUT /api/admin/knowledge/readings/{id} — partial update.
//
// Convenience rule: a transition to status=finished with no finished_on in
// the request sets finished_on to today. An explicit finished_on always
// wins, and an already-recorded finish date is never overwritten by the
// auto-stamp (resolution order lives in the UpdateReading query).
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid reading id")
		return
	}
	req, err := api.Decode[updateRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Title != nil {
		if strings.TrimSpace(*req.Title) == "" {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title must not be blank")
			return
		}
		if containsControlChars(*req.Title) {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title must not contain control characters")
			return
		}
	}
	if req.Author != nil && containsControlChars(*req.Author) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "author must not contain control characters")
		return
	}
	if req.Status != nil && !req.Status.Valid() {
		api.Error(w, http.StatusBadRequest, "INVALID_STATUS", "invalid reading status")
		return
	}
	startedOn, ok := parseDate(w, req.StartedOn, "started_on")
	if !ok {
		return
	}
	finishedOn, ok := parseDate(w, req.FinishedOn, "finished_on")
	if !ok {
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	rd, err := store.Update(r.Context(), id, UpdateParams{
		Title:      req.Title,
		Author:     req.Author,
		Status:     req.Status,
		StartedOn:  startedOn,
		FinishedOn: finishedOn,
		IsPublic:   req.IsPublic,
	})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: toReadingResponse(rd)})
}

// Delete handles DELETE /api/admin/knowledge/readings/{id}. Deleting a
// book deletes its entire diary (ON DELETE CASCADE).
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid reading id")
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

// createReflectionRequest is the POST body for CreateReflection.
type createReflectionRequest struct {
	Body      string  `json:"body"`
	EntryDate *string `json:"entry_date,omitempty"`
}

// CreateReflection handles POST /api/admin/knowledge/readings/{id}/reflections.
// entry_date defaults to today when omitted. Body is multi-line prose —
// newlines and tabs are allowed, other control characters are not.
func (h *Handler) CreateReflection(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid reading id")
		return
	}
	req, err := api.Decode[createReflectionRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if strings.TrimSpace(req.Body) == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "body is required")
		return
	}
	if containsProseControlChars(req.Body) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "body must not contain control characters")
		return
	}
	entryDate, ok := parseDate(w, req.EntryDate, "entry_date")
	if !ok {
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	ref, err := store.CreateReflection(r.Context(), id, entryDate, req.Body)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: toReflectionResponse(ref)})
}

// updateReflectionRequest is the PUT body for UpdateReflection.
type updateReflectionRequest struct {
	Body      *string `json:"body,omitempty"`
	EntryDate *string `json:"entry_date,omitempty"`
}

// UpdateReflection handles
// PUT /api/admin/knowledge/readings/{id}/reflections/{rid}. The reflection
// must belong to the reading — a mismatch is a 404, never a cross-book
// write (membership is bound in the store's WHERE clause).
func (h *Handler) UpdateReflection(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid reading id")
		return
	}
	rid, err := uuid.Parse(r.PathValue("rid"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid reflection id")
		return
	}
	req, err := api.Decode[updateReflectionRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Body != nil {
		if strings.TrimSpace(*req.Body) == "" {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "body must not be blank")
			return
		}
		if containsProseControlChars(*req.Body) {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "body must not contain control characters")
			return
		}
	}
	entryDate, ok := parseDate(w, req.EntryDate, "entry_date")
	if !ok {
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	ref, err := store.UpdateReflection(r.Context(), id, rid, UpdateReflectionParams{
		Body:      req.Body,
		EntryDate: entryDate,
	})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: toReflectionResponse(ref)})
}

// DeleteReflection handles
// DELETE /api/admin/knowledge/readings/{id}/reflections/{rid}. Same
// membership binding as UpdateReflection — a mismatch is a 404.
func (h *Handler) DeleteReflection(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid reading id")
		return
	}
	rid, err := uuid.Parse(r.PathValue("rid"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid reflection id")
		return
	}
	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	if err := store.DeleteReflection(r.Context(), id, rid); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseDate parses an optional YYYY-MM-DD wire string. A nil input is
// nil output. On a malformed value it writes a 400 naming the field and
// reports ok=false.
func parseDate(w http.ResponseWriter, raw *string, field string) (parsed *time.Time, ok bool) {
	if raw == nil {
		return nil, true
	}
	t, err := time.Parse(time.DateOnly, *raw)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", field+" must be a YYYY-MM-DD date")
		return nil, false
	}
	return &t, true
}

// toReadingResponse converts a domain Reading into its wire shape.
func toReadingResponse(rd *Reading) readingResponse {
	return readingResponse{
		ID:         rd.ID,
		Title:      rd.Title,
		Author:     rd.Author,
		Status:     rd.Status,
		StartedOn:  dateString(rd.StartedOn),
		FinishedOn: dateString(rd.FinishedOn),
		IsPublic:   rd.IsPublic,
		CreatedAt:  rd.CreatedAt,
		UpdatedAt:  rd.UpdatedAt,
	}
}

// toReflectionResponse converts a domain Reflection into its wire shape.
func toReflectionResponse(ref *Reflection) reflectionResponse {
	return reflectionResponse{
		ID:        ref.ID,
		ReadingID: ref.ReadingID,
		EntryDate: ref.EntryDate.Format(time.DateOnly),
		Body:      ref.Body,
		CreatedAt: ref.CreatedAt,
		UpdatedAt: ref.UpdatedAt,
	}
}

// dateString formats an optional DATE as YYYY-MM-DD, nil-preserving.
func dateString(t *time.Time) *string {
	if t == nil {
		return nil
	}
	return new(t.Format(time.DateOnly))
}
