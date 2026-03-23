package tag

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/blog-backend/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT"},
	{Target: ErrHasReferences, Status: http.StatusConflict, Code: "HAS_REFERENCES"},
}

// Input length limits for tag fields.
const (
	maxSlugLen = 100
	maxNameLen = 200
	maxDescLen = 1000
)

// Handler handles tag and alias admin HTTP requests.
type Handler struct {
	store  *Store
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewHandler returns a tag Handler. Pool is needed for transactional merge operations.
func NewHandler(store *Store, pool *pgxpool.Pool, logger *slog.Logger) *Handler {
	return &Handler{store: store, pool: pool, logger: logger}
}

// List handles GET /api/admin/tags — returns all canonical tags.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	tags, err := h.store.Tags(r.Context())
	if err != nil {
		h.logger.Error("listing tags", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list tags")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: tags})
}

// Create handles POST /api/admin/tags.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Slug == "" || p.Name == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug and name are required")
		return
	}
	if len(p.Slug) > maxSlugLen || len(p.Name) > maxNameLen || len(p.Description) > maxDescLen {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "field exceeds maximum length")
		return
	}

	t, err := h.store.CreateTag(r.Context(), &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: t})
}

// Update handles PUT /api/admin/tags/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid tag id")
		return
	}

	p, err := api.Decode[UpdateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if p.Slug == nil && p.Name == nil && p.ParentID == nil && p.Description == nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "at least one field must be provided")
		return
	}
	if (p.Slug != nil && len(*p.Slug) > maxSlugLen) ||
		(p.Name != nil && len(*p.Name) > maxNameLen) ||
		(p.Description != nil && len(*p.Description) > maxDescLen) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "field exceeds maximum length")
		return
	}

	t, err := h.store.UpdateTag(r.Context(), id, &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: t})
}

// Delete handles DELETE /api/admin/tags/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid tag id")
		return
	}

	if err := h.store.DeleteTag(r.Context(), id); err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListAliases handles GET /api/admin/aliases.
// Query param ?unmapped=true filters to unmapped aliases only.
func (h *Handler) ListAliases(w http.ResponseWriter, r *http.Request) {
	var (
		aliases []Alias
		err     error
	)
	if r.URL.Query().Get("unmapped") == "true" {
		aliases, err = h.store.UnmappedAliases(r.Context())
	} else {
		aliases, err = h.store.Aliases(r.Context())
	}
	if err != nil {
		h.logger.Error("listing aliases", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list aliases")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: aliases})
}

// MapAlias handles POST /api/admin/aliases/{id}/map.
func (h *Handler) MapAlias(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid alias id")
		return
	}

	p, err := api.Decode[MapAliasParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.TagID == uuid.Nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "tag_id is required")
		return
	}

	a, err := h.store.MapAlias(r.Context(), id, p.TagID)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: a})
}

// ConfirmAlias handles POST /api/admin/aliases/{id}/confirm.
func (h *Handler) ConfirmAlias(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid alias id")
		return
	}

	a, err := h.store.ConfirmAlias(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: a})
}

// RejectAlias handles POST /api/admin/aliases/{id}/reject.
func (h *Handler) RejectAlias(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid alias id")
		return
	}

	a, err := h.store.RejectAlias(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: a})
}

// DeleteAlias handles DELETE /api/admin/aliases/{id}.
func (h *Handler) DeleteAlias(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid alias id")
		return
	}

	if err := h.store.DeleteAlias(r.Context(), id); err != nil {
		h.logger.Error("deleting alias", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete alias")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Backfill handles POST /api/admin/tags/backfill.
// Scans all obsidian notes with raw tags, resolves through tag aliases,
// and writes resolved tag IDs to the obsidian_note_tags junction table.
func (h *Handler) Backfill(w http.ResponseWriter, r *http.Request) {
	result, err := h.store.BackfillNoteTags(r.Context())
	if err != nil {
		h.logger.Error("backfilling note tags", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to backfill tags")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: result})
}

// Merge handles POST /api/admin/tags/merge.
// Merges source tag into target: reassigns all aliases, note-tags, event-tags,
// then deletes the source tag. Runs in a transaction.
func (h *Handler) Merge(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[MergeParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.SourceID == uuid.Nil || p.TargetID == uuid.Nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "source_id and target_id are required")
		return
	}
	if p.SourceID == p.TargetID {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "source_id and target_id must be different")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.logger.Error("beginning merge transaction", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to begin transaction")
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck // rollback on committed tx is no-op

	result, err := h.store.MergeTags(r.Context(), tx, p.SourceID, p.TargetID)
	if err != nil {
		h.logger.Error("merging tags", "source", p.SourceID, "target", p.TargetID, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to merge tags")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("committing merge transaction", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to commit merge")
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: result})
}
