// Copyright 2026 Koopa. All rights reserved.

// handler.go holds the admin HTTP handlers for the ヨルシカ song shelf and its
// reflection diary. Every route lives under /api/admin/knowledge/songs —
// there is no public and no MCP surface for this domain (privacy boundary,
// see the package comment). Mutation routes are wired through adminMid in
// cmd/app/routes.go, so handlers route writes through the per-request tx even
// though no audit triggers fire on these tables.
//
// The study fields (lyrics_ja, translation, vocabulary) are owner-filled
// free text: handlers accept and store what the client sends, they never
// synthesize content. entry_date crosses the wire as a YYYY-MM-DD string —
// it is a DATE column, not a timestamp.

package song

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses. The store only
// surfaces ErrNotFound: songs have no status enum to validate, so all
// blank/control-char rejection happens in the handler before any store call
// (unlike reading, whose store returns ErrInvalidInput for a bad status).
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "song or reflection not found"},
}

// Handler handles song HTTP requests. The surface is admin-only: reads
// behind authMid, mutations behind adminMid.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a song Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// mustAdminTx extracts the request-scoped pgx.Tx supplied by
// api.ActorMiddleware so mutations stay inside the per-request tx.
func (h *Handler) mustAdminTx(w http.ResponseWriter, r *http.Request) (store *Store, ok bool) {
	tx, ok := api.TxFromContext(r.Context())
	if !ok {
		h.logger.Error("song admin mutation without tx",
			"event", "middleware_not_wired",
			"method", r.Method, "path", r.URL.Path)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
		return nil, false
	}
	return h.store.WithTx(tx), true
}

// songResponse is the wire shape of a song.
type songResponse struct {
	ID          uuid.UUID `json:"id"`
	TitleJa     string    `json:"title_ja"`
	Album       string    `json:"album"`
	LyricsJa    string    `json:"lyrics_ja"`
	Translation string    `json:"translation"`
	Vocabulary  string    `json:"vocabulary"`
	IsPublic    bool      `json:"is_public"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// reflectionResponse is the wire shape of a diary entry.
type reflectionResponse struct {
	ID        uuid.UUID `json:"id"`
	SongID    uuid.UUID `json:"song_id"`
	EntryDate string    `json:"entry_date"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// songDetail is the song page: the song plus its diary thread in entry_date
// order (created_at tiebreak).
type songDetail struct {
	songResponse
	Reflections []reflectionResponse `json:"reflections"`
}

// List handles GET /api/admin/knowledge/songs. Ordered by updated_at
// descending — album grouping for the shelf is the frontend's call.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	songs, err := h.store.Songs(r.Context())
	if err != nil {
		h.logger.Error("listing songs", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list songs")
		return
	}
	out := make([]songResponse, len(songs))
	for i := range songs {
		out[i] = toSongResponse(&songs[i])
	}
	api.Encode(w, http.StatusOK, api.Response{Data: out})
}

// Get handles GET /api/admin/knowledge/songs/{id} — the song plus its full
// reflection thread.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid song id")
		return
	}
	sg, err := h.store.Song(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	refs, err := h.store.Reflections(r.Context(), id)
	if err != nil {
		h.logger.Error("listing reflections", "song_id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to load reflections")
		return
	}
	detail := songDetail{
		songResponse: toSongResponse(sg),
		Reflections:  make([]reflectionResponse, len(refs)),
	}
	for i := range refs {
		detail.Reflections[i] = toReflectionResponse(&refs[i])
	}
	api.Encode(w, http.StatusOK, api.Response{Data: detail})
}

// createRequest is the POST body for Create. The study fields are optional —
// they default to empty for the owner to fill later.
type createRequest struct {
	Title       string `json:"title_ja"`
	Album       string `json:"album,omitempty"`
	LyricsJa    string `json:"lyrics_ja,omitempty"`
	Translation string `json:"translation,omitempty"`
	Vocabulary  string `json:"vocabulary,omitempty"`
}

// validateSingleLine writes a 400 and returns false if v contains a control
// character forbidden in single-line fields (title_ja, album). Empty is
// allowed — blank-ness is the caller's separate concern.
func validateSingleLine(w http.ResponseWriter, v, field string) bool {
	if containsControlChars(v) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", field+" must not contain control characters")
		return false
	}
	return true
}

// validateProse writes a 400 and returns false if v contains a control
// character forbidden in multi-line prose (the study fields and reflection
// bodies — newlines and tabs are legitimate).
func validateProse(w http.ResponseWriter, v, field string) bool {
	if containsProseControlChars(v) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", field+" must not contain control characters")
		return false
	}
	return true
}

// validateOptionalSingleLine applies validateSingleLine to a partial-update
// pointer field: a nil pointer is "unchanged" and always passes.
func validateOptionalSingleLine(w http.ResponseWriter, v *string, field string) bool {
	return v == nil || validateSingleLine(w, *v, field)
}

// validateOptionalProse applies validateProse to a partial-update pointer
// field: a nil pointer is "unchanged" and always passes.
func validateOptionalProse(w http.ResponseWriter, v *string, field string) bool {
	return v == nil || validateProse(w, *v, field)
}

// Create handles POST /api/admin/knowledge/songs.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[createRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title_ja is required")
		return
	}
	if !validateSingleLine(w, req.Title, "title_ja") ||
		!validateSingleLine(w, req.Album, "album") ||
		!validateProse(w, req.LyricsJa, "lyrics_ja") ||
		!validateProse(w, req.Translation, "translation") ||
		!validateProse(w, req.Vocabulary, "vocabulary") {
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	sg, err := store.Create(r.Context(), &CreateParams{
		Title:       req.Title,
		Album:       req.Album,
		LyricsJa:    req.LyricsJa,
		Translation: req.Translation,
		Vocabulary:  req.Vocabulary,
	})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: toSongResponse(sg)})
}

// updateRequest is the PUT body for Update. All fields optional; omitted
// fields stay unchanged.
type updateRequest struct {
	Title       *string `json:"title_ja,omitempty"`
	Album       *string `json:"album,omitempty"`
	LyricsJa    *string `json:"lyrics_ja,omitempty"`
	Translation *string `json:"translation,omitempty"`
	Vocabulary  *string `json:"vocabulary,omitempty"`
	IsPublic    *bool   `json:"is_public,omitempty"`
}

// Update handles PUT /api/admin/knowledge/songs/{id} — partial update.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid song id")
		return
	}
	req, err := api.Decode[updateRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Title != nil && strings.TrimSpace(*req.Title) == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title_ja must not be blank")
		return
	}
	if !validateOptionalSingleLine(w, req.Title, "title_ja") ||
		!validateOptionalSingleLine(w, req.Album, "album") ||
		!validateOptionalProse(w, req.LyricsJa, "lyrics_ja") ||
		!validateOptionalProse(w, req.Translation, "translation") ||
		!validateOptionalProse(w, req.Vocabulary, "vocabulary") {
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	//nolint:staticcheck // S1016: wire (updateRequest) and domain (UpdateParams)
	// types are kept distinct per json-api.md; the field mapping is the
	// validation boundary, not an accidental conversion.
	sg, err := store.Update(r.Context(), id, UpdateParams{
		Title:       req.Title,
		Album:       req.Album,
		LyricsJa:    req.LyricsJa,
		Translation: req.Translation,
		Vocabulary:  req.Vocabulary,
		IsPublic:    req.IsPublic,
	})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: toSongResponse(sg)})
}

// Delete handles DELETE /api/admin/knowledge/songs/{id}. Deleting a song
// deletes its entire reflection thread (ON DELETE CASCADE).
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid song id")
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

// CreateReflection handles POST /api/admin/knowledge/songs/{id}/reflections.
// entry_date defaults to today when omitted. Body is multi-line prose —
// newlines and tabs are allowed, other control characters are not.
func (h *Handler) CreateReflection(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid song id")
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
// PUT /api/admin/knowledge/songs/{id}/reflections/{rid}. The reflection must
// belong to the song — a mismatch is a 404, never a cross-song write
// (membership is bound in the store's WHERE clause).
func (h *Handler) UpdateReflection(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid song id")
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
// DELETE /api/admin/knowledge/songs/{id}/reflections/{rid}. Same membership
// binding as UpdateReflection — a mismatch is a 404.
func (h *Handler) DeleteReflection(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid song id")
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

// parseDate parses an optional YYYY-MM-DD wire string. A nil input is nil
// output. On a malformed value it writes a 400 naming the field and reports
// ok=false.
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

// toSongResponse converts a domain Song into its wire shape.
func toSongResponse(sg *Song) songResponse {
	return songResponse{
		ID:          sg.ID,
		TitleJa:     sg.TitleJa,
		Album:       sg.Album,
		LyricsJa:    sg.LyricsJa,
		Translation: sg.Translation,
		Vocabulary:  sg.Vocabulary,
		IsPublic:    sg.IsPublic,
		CreatedAt:   sg.CreatedAt,
		UpdatedAt:   sg.UpdatedAt,
	}
}

// toReflectionResponse converts a domain Reflection into its wire shape.
func toReflectionResponse(ref *Reflection) reflectionResponse {
	return reflectionResponse{
		ID:        ref.ID,
		SongID:    ref.SongID,
		EntryDate: ref.EntryDate.Format(time.DateOnly),
		Body:      ref.Body,
		CreatedAt: ref.CreatedAt,
		UpdatedAt: ref.UpdatedAt,
	}
}
