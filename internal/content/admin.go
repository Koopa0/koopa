// Copyright 2026 Koopa. All rights reserved.

// admin.go holds the authenticated admin HTTP handlers and the
// Contents store method they share. All mutation paths —
// Create / Update / Delete / SetIsPublic — go through adminMid in
// cmd/app/routes.go, so the per-request tx in context carries
// koopa.actor and audit triggers record the real mutator.
//
// publish.go owns the publish-specific mutation (visibility gate).
// public.go owns the anonymous read surface. Keeping these three
// split avoids accidentally exposing an admin method as public.

package content

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/db"
)

// containsControlChars reports whether s contains any control character — ASCII
// C0 (0x00–0x1F), DEL (0x7F), or Unicode C1 (0x80–0x9F). This is the strict
// single-line check for title/excerpt; it is the same predicate the MCP write
// path applies via goal.ContainsControlChars (kept local here because content
// cannot import goal without an import cycle: content → goal → project →
// content). Body uses containsProseControlChars instead, which permits HT/LF/CR.
func containsControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}

// checkContentControlChars rejects control characters in the content write
// fields. slug, title, and excerpt are single-line fields validated with the
// strict check (every control char), while body is multi-line Markdown
// validated with the prose check (HT/LF/CR permitted). This mirrors the MCP
// write path for title/excerpt/body (propose_content / revise_content); slug is
// admin-only — the MCP path derives the slug server-side, and the DB
// slug-format CHECK rejects whitespace and slashes but NOT non-whitespace
// control chars, so this is the boundary that keeps them out of the URL path
// segment. A nil argument is skipped so the same check serves Create (all
// present) and partial Update (only changed fields). Returns the first
// offending field name, or "" when clean.
func checkContentControlChars(slug, title, excerpt, body *string) string {
	if slug != nil && containsControlChars(*slug) {
		return "slug"
	}
	if title != nil && containsControlChars(*title) {
		return "title"
	}
	if excerpt != nil && containsControlChars(*excerpt) {
		return "excerpt"
	}
	if body != nil && containsProseControlChars(*body) {
		return "body"
	}
	return ""
}

// containsProseControlChars reports whether s contains a control character
// forbidden in multi-line free-text prose: every control char EXCEPT HT (0x09),
// LF (0x0A), and CR (0x0D). Body and review_note are short, possibly multi-line
// free text where line breaks are legitimate, so they are validated with this
// rather than the strict containsControlChars above. Mirrors the MCP prose check.
func containsProseControlChars(s string) bool {
	for _, r := range s {
		switch {
		case r == 0x09, r == 0x0a, r == 0x0d:
			continue
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			return true
		}
	}
	return false
}

// Contents returns a paginated list across all statuses / visibilities.
// The authenticated admin listing route consumes this; the public-facing
// variant is PublicContents.
func (s *Store) Contents(ctx context.Context, f Filter) ([]Content, int, error) {
	ct := nullContentType(f.Type)

	cs := nullContentStatus(f.Status)

	rows, err := s.q.ListContents(ctx, db.ListContentsParams{
		Limit:         int32(f.PerPage),                // #nosec G115 -- pagination values are bounded by API layer
		Offset:        int32((f.Page - 1) * f.PerPage), // #nosec G115 -- pagination values are bounded by API layer
		ContentType:   ct,
		ContentStatus: cs,
		IsPublic:      f.IsPublic,
		ProjectID:     f.Project,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing contents: %w", err)
	}

	countRow, err := s.q.CountContents(ctx, db.CountContentsParams{
		ContentType:   ct,
		ContentStatus: cs,
		IsPublic:      f.IsPublic,
		ProjectID:     f.Project,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("counting contents: %w", err)
	}

	contents := make([]Content, len(rows))
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		r := rows[i]
		contents[i] = Content{
			ID:                r.ID,
			Slug:              r.Slug,
			Title:             r.Title,
			Excerpt:           r.Excerpt,
			Type:              Type(r.Type),
			Status:            Status(r.Status),
			IsPublic:          r.IsPublic,
			ProjectID:         r.ProjectID,
			ReadingTimeMin:    int(r.ReadingTimeMin),
			CreatedBy:         r.CreatedBy,
			ProposalRationale: r.ProposalRationale,
			PublishedAt:       r.PublishedAt,
			CreatedAt:         r.CreatedAt,
			UpdatedAt:         r.UpdatedAt,
		}
		ids[i] = r.ID
	}

	if err := s.attachBatchTopics(ctx, contents, ids); err != nil {
		return nil, 0, err
	}

	return contents, int(countRow), nil
}

// handleSlugConflict renders SlugConflictError as a 409 with the existing
// row's identity. Returns true when it handled the error.
func handleSlugConflict(w http.ResponseWriter, err error) bool {
	if se, ok := errors.AsType[*SlugConflictError](err); ok {
		api.Encode(w, http.StatusConflict, slugConflictBody{
			Error: slugConflictDetail{
				Code:      "SLUG_CONFLICT",
				Message:   se.Error(),
				Slug:      se.Slug,
				ContentID: se.ContentID.String(),
			},
		})
		return true
	}
	return false
}

// Create handles POST /api/admin/contents.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Slug == "" || p.Title == "" || p.Type == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug, title, and type are required")
		return
	}
	if !p.Type.Valid() {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content type")
		return
	}
	if err := CheckFieldLengths(&p.Title, &p.Excerpt, &p.Body); err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	if field := checkContentControlChars(&p.Slug, &p.Title, &p.Excerpt, &p.Body); field != "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", field+" must not contain control characters")
		return
	}
	if p.Status == "" {
		p.Status = StatusDraft
	}
	if !p.Status.Valid() {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content status")
		return
	}
	// IsPublic defaults to false (zero value for bool) — callers set explicitly if needed

	tx, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	c, err := h.store.WithTx(tx).CreateContent(r.Context(), &p)
	if err != nil {
		if handleSlugConflict(w, err) {
			return
		}
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: c})
}

// Update handles PUT /api/admin/contents/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}

	p, err := api.Decode[UpdateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Type != nil && !p.Type.Valid() {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content type")
		return
	}
	if p.Status != nil && !p.Status.Valid() {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content status")
		return
	}
	if err := CheckFieldLengths(p.Title, p.Excerpt, p.Body); err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	if field := checkContentControlChars(p.Slug, p.Title, p.Excerpt, p.Body); field != "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", field+" must not contain control characters")
		return
	}
	// IsPublic is a bool pointer — no validation needed beyond JSON decode

	tx, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	c, err := h.store.WithTx(tx).UpdateContent(r.Context(), id, &p)
	if err != nil {
		if handleSlugConflict(w, err) {
			return
		}
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

// Delete handles DELETE /api/admin/contents/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}

	tx, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	if err := h.store.WithTx(tx).DeleteContent(r.Context(), id); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Publish handles POST /api/admin/knowledge/content/{id}/publish.
// State-guarded per the editorial lifecycle (Policy B): only a review row is
// promoted; an already-published row is an idempotent success; draft and
// archived are rejected with 400 INVALID_STATE. The gate lives in
// content.Store.PublishFromReview. Publishing is admin HTTP only — no MCP tool
// publishes; an agent's reach ends at propose_content (lands at status=review).
func (h *Handler) Publish(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}

	tx, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	c, err := h.store.WithTx(tx).PublishFromReview(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

// Get handles GET /api/admin/knowledge/content/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}

	c, err := h.store.Content(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

// List handles GET /api/admin/knowledge/content.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f, ok := parseAdminListFilter(w, r)
	if !ok {
		return
	}

	contents, total, err := h.store.Contents(r.Context(), f)
	if err != nil {
		h.logger.Error("admin listing contents", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list contents")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(contents, total, f.Page, f.PerPage))
}

// parseAdminListFilter builds a Filter from the admin List query parameters,
// rejecting unrecognized type, status, or is_public values with 400. An
// unrecognized value left the filter pointer nil, which silently applied no
// filter (a wrongly broad result set); validation here keeps the contract
// consistent across all three filters. Returns false after writing the error
// response when any value is invalid.
func parseAdminListFilter(w http.ResponseWriter, r *http.Request) (Filter, bool) {
	page, perPage := api.ParsePagination(r)
	f := Filter{Page: page, PerPage: perPage}

	if t := r.URL.Query().Get("type"); t != "" {
		ct := Type(t)
		if ct.Valid() {
			f.Type = &ct
		} else {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content type")
			return Filter{}, false
		}
	}
	if s := r.URL.Query().Get("status"); s != "" {
		cs := Status(s)
		switch cs {
		case StatusDraft, StatusReview, StatusChangesRequested, StatusPublished, StatusArchived:
			f.Status = &cs
		default:
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content status")
			return Filter{}, false
		}
	}
	if v := r.URL.Query().Get("is_public"); v != "" {
		switch v {
		case "true":
			isPublic := true
			f.IsPublic = &isPublic
		case "false":
			isPublic := false
			f.IsPublic = &isPublic
		default:
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "is_public must be true or false")
			return Filter{}, false
		}
	}
	return f, true
}

// SubmitForReview handles POST /api/admin/knowledge/content/{id}/submit-for-review.
// Transitions draft → review. Returns 400 INVALID_STATE when the content is
// not in draft.
func (h *Handler) SubmitForReview(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}
	tx, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	c, err := h.store.WithTx(tx).SubmitContentForReview(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

// RevertToDraft handles POST /api/admin/knowledge/content/{id}/revert-to-draft.
// Transitions review → draft (reviewer rejection). Returns 400 INVALID_STATE
// when the content is not in review.
func (h *Handler) RevertToDraft(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}
	tx, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	c, err := h.store.WithTx(tx).RevertContentToDraft(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

// sendBackBody is the request payload for SendBack: the owner's revision reason.
type sendBackBody struct {
	ReviewNote string `json:"review_note"`
}

// SendBack handles POST /api/admin/knowledge/content/{id}/send-back.
// Transitions review → changes_requested with the owner's review_note reason.
// Rejects an empty/whitespace review_note (400) and any control characters
// other than line breaks/tabs (400). Returns 400 INVALID_STATE when the content
// is not in review.
func (h *Handler) SendBack(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}

	body, decErr := api.Decode[sendBackBody](w, r)
	if decErr != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	reviewNote := strings.TrimSpace(body.ReviewNote)
	if reviewNote == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "review_note is required")
		return
	}
	if containsProseControlChars(reviewNote) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "review_note must not contain control characters")
		return
	}
	if err := CheckReviewNoteLength(reviewNote); err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	tx, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	c, err := h.store.WithTx(tx).SendBackForChanges(r.Context(), id, reviewNote)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

// Archive handles POST /api/admin/knowledge/content/{id}/archive.
// Unconditional → archived; returns the updated row.
func (h *Handler) Archive(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}
	tx, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	c, err := h.store.WithTx(tx).ArchiveContentReturning(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

// SetIsPublic handles PATCH /api/admin/contents/{id}/is-public.
func (h *Handler) SetIsPublic(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}

	type isPublicBody struct {
		IsPublic bool `json:"is_public"`
	}
	body, decErr := api.Decode[isPublicBody](w, r)
	if decErr != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	tx, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	c, err := h.store.WithTx(tx).UpdateContent(r.Context(), id, &UpdateParams{IsPublic: &body.IsPublic})
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}
