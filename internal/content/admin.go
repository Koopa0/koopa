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

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/db"
)

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
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing contents: %w", err)
	}

	countRow, err := s.q.CountContents(ctx, db.CountContentsParams{
		ContentType:   ct,
		ContentStatus: cs,
		IsPublic:      f.IsPublic,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("counting contents: %w", err)
	}

	contents := make([]Content, len(rows))
	for i := range rows {
		r := rows[i]
		contents[i] = Content{
			ID:             r.ID,
			Slug:           r.Slug,
			Title:          r.Title,
			Excerpt:        r.Excerpt,
			Type:           Type(r.Type),
			Status:         Status(r.Status),
			IsPublic:       r.IsPublic,
			ProjectID:      r.ProjectID,
			ReadingTimeMin: int(r.ReadingTimeMin),
			PublishedAt:    r.PublishedAt,
			CreatedAt:      r.CreatedAt,
			UpdatedAt:      r.UpdatedAt,
		}
	}

	return contents, int(countRow), nil
}

// handleSlugConflict renders SlugConflictError as a 409 with the existing
// row's identity. Returns true when it handled the error.
func handleSlugConflict(w http.ResponseWriter, err error) bool {
	var se *SlugConflictError
	if errors.As(err, &se) {
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
	if p.Status == "" {
		p.Status = StatusDraft
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
		h.logger.Error("deleting content", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete content")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Publish handles POST /api/admin/contents/{id}/publish.
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
	c, err := h.store.WithTx(tx).PublishContent(r.Context(), id)
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
	page, perPage := api.ParsePagination(r)
	f := Filter{Page: page, PerPage: perPage}

	if t := r.URL.Query().Get("type"); t != "" {
		ct := Type(t)
		if ct.Valid() {
			f.Type = &ct
		}
	}
	if s := r.URL.Query().Get("status"); s != "" {
		cs := Status(s)
		switch cs {
		case StatusDraft, StatusReview, StatusPublished, StatusArchived:
			f.Status = &cs
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
			return
		}
	}

	contents, total, err := h.store.Contents(r.Context(), f)
	if err != nil {
		h.logger.Error("admin listing contents", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list contents")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(contents, total, f.Page, f.PerPage))
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
