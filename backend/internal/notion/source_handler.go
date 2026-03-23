package notion

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// sourceStoreErrors maps source store sentinel errors to HTTP responses.
var sourceStoreErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT"},
}

// SyncTrigger triggers a sync for a specific role or all roles.
type SyncTrigger interface {
	SyncAll(ctx context.Context)
	SyncRoleAsync(ctx context.Context, role string)
}

// SourceHandler handles admin HTTP requests for notion source CRUD.
type SourceHandler struct {
	store       *Store
	client      *Client
	sourceCache *ristretto.Cache[string, string]
	syncer      SyncTrigger
	logger      *slog.Logger
}

// NewSourceHandler returns a SourceHandler.
func NewSourceHandler(store *Store, client *Client, sourceCache *ristretto.Cache[string, string], logger *slog.Logger) *SourceHandler {
	return &SourceHandler{store: store, client: client, sourceCache: sourceCache, logger: logger}
}

// SetSyncer sets the sync trigger for immediate sync after role assignment.
func (h *SourceHandler) SetSyncer(s SyncTrigger) {
	h.syncer = s
}

// Discover handles GET /api/admin/notion-sources/discover.
// Lists all Notion databases accessible by the integration token.
func (h *SourceHandler) Discover(w http.ResponseWriter, r *http.Request) {
	if h.client == nil {
		api.Error(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "notion API not configured")
		return
	}

	dbs, err := h.client.SearchDatabases(r.Context())
	if err != nil {
		h.logger.Error("discovering notion databases", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to discover databases")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: dbs})
}

// List handles GET /api/admin/notion-sources.
func (h *SourceHandler) List(w http.ResponseWriter, r *http.Request) {
	sources, err := h.store.Sources(r.Context())
	if err != nil {
		h.logger.Error("listing notion sources", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list notion sources")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: sources})
}

// ByID handles GET /api/admin/notion-sources/{id}.
func (h *SourceHandler) ByID(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid source id")
		return
	}

	src, err := h.store.Source(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, sourceStoreErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: src})
}

// Create handles POST /api/admin/notion-sources.
func (h *SourceHandler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateSourceParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.DatabaseID == "" || p.Name == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "database_id and name are required")
		return
	}
	if len(p.DatabaseID) > 255 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "database_id exceeds 255 characters")
		return
	}
	if len(p.Name) > 255 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "name exceeds 255 characters")
		return
	}
	if len([]rune(p.Description)) > 1024 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "description exceeds 1024 characters")
		return
	}
	if p.Role != nil && !ValidRole(*p.Role) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid role, must be 'projects', 'tasks', 'books', or 'goals'")
		return
	}
	if p.SyncMode == "" {
		p.SyncMode = SyncModeFull
	}
	if !ValidSyncMode(p.SyncMode) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid sync_mode, must be 'full' or 'events'")
		return
	}
	if p.PollInterval == "" {
		p.PollInterval = "15 minutes"
	}
	if !ValidPollInterval(p.PollInterval) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid poll_interval")
		return
	}
	if p.PropertyMap == nil {
		p.PropertyMap = []byte("{}")
	}
	if len(p.PropertyMap) > 64*1024 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "property_map exceeds 64 KB")
		return
	}
	if !json.Valid(p.PropertyMap) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "property_map is not valid JSON")
		return
	}

	src, err := h.store.CreateSource(r.Context(), &p)
	if err != nil {
		api.HandleError(w, h.logger, err, sourceStoreErrors...)
		return
	}
	h.invalidateCache(src.DatabaseID)
	// trigger immediate sync for the assigned role only (not all databases)
	if src.Role != nil && *src.Role != "" && h.syncer != nil {
		h.syncer.SyncRoleAsync(context.WithoutCancel(r.Context()), *src.Role)
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: src})
}

// Update handles PUT /api/admin/notion-sources/{id}.
func (h *SourceHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid source id")
		return
	}

	p, err := api.Decode[UpdateSourceParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.SyncMode != nil && !ValidSyncMode(*p.SyncMode) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid sync_mode, must be 'full' or 'events'")
		return
	}
	if p.Name != nil && *p.Name == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "name cannot be empty")
		return
	}
	if p.Name != nil && len(*p.Name) > 255 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "name exceeds 255 characters")
		return
	}
	if p.PollInterval != nil && !ValidPollInterval(*p.PollInterval) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid poll_interval")
		return
	}
	if p.PropertyMap != nil && len(*p.PropertyMap) > 64*1024 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "property_map exceeds 64 KB")
		return
	}
	if p.PropertyMap != nil && !json.Valid(*p.PropertyMap) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "property_map is not valid JSON")
		return
	}

	src, err := h.store.UpdateSource(r.Context(), id, &p)
	if err != nil {
		api.HandleError(w, h.logger, err, sourceStoreErrors...)
		return
	}
	h.invalidateCache(src.DatabaseID)
	api.Encode(w, http.StatusOK, api.Response{Data: src})
}

// Delete handles DELETE /api/admin/notion-sources/{id}.
func (h *SourceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid source id")
		return
	}

	// look up database_id for cache invalidation before deleting
	src, lookupErr := h.store.Source(r.Context(), id)

	if err := h.store.DeleteSource(r.Context(), id); err != nil {
		api.HandleError(w, h.logger, err, sourceStoreErrors...)
		return
	}
	if lookupErr == nil {
		h.invalidateCache(src.DatabaseID)
	}
	w.WriteHeader(http.StatusNoContent)
}

// Toggle handles POST /api/admin/notion-sources/{id}/toggle.
func (h *SourceHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid source id")
		return
	}

	src, err := h.store.ToggleEnabled(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, sourceStoreErrors...)
		return
	}
	h.invalidateCache(src.DatabaseID)
	api.Encode(w, http.StatusOK, api.Response{Data: src})
}

// setRoleRequest is the JSON body for the SetRole endpoint.
type setRoleRequest struct {
	Role *string `json:"role"`
}

// SetRole handles PUT /api/admin/notion-sources/{id}/role.
func (h *SourceHandler) SetRole(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid source id")
		return
	}

	req, err := api.Decode[setRoleRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if req.Role != nil && !ValidRole(*req.Role) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid role, must be 'projects', 'tasks', 'books', or 'goals'")
		return
	}

	if roleErr := h.applyRole(r.Context(), id, req.Role); roleErr != nil {
		h.handleRoleError(w, roleErr, id, req.Role)
		return
	}

	// invalidate all cached entries — role change can affect multiple sources
	h.sourceCache.Clear()

	// trigger immediate sync for the assigned role only
	if h.syncer != nil && req.Role != nil && *req.Role != "" {
		h.syncer.SyncRoleAsync(context.WithoutCancel(r.Context()), *req.Role)
	}

	src, err := h.store.Source(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, sourceStoreErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: src})
}

// applyRole sets or clears a role on a notion source.
func (h *SourceHandler) applyRole(ctx context.Context, id uuid.UUID, role *string) error {
	if role != nil && *role != "" {
		return h.store.SetRole(ctx, id, *role)
	}
	return h.store.ClearSourceRole(ctx, id)
}

// handleRoleError maps a role operation error to an HTTP response.
func (h *SourceHandler) handleRoleError(w http.ResponseWriter, err error, _ uuid.UUID, _ *string) {
	api.HandleError(w, h.logger, err, sourceStoreErrors...)
}

// invalidateCache removes a database_id from the source cache.
func (h *SourceHandler) invalidateCache(databaseID string) {
	h.sourceCache.Del(databaseID)
}
