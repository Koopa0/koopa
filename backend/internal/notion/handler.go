package notion

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/task"
	"github.com/koopa0/blog-backend/internal/webhook"
)

// sourceCacheTTL is how long a database_id → role mapping stays in cache.
const sourceCacheTTL = 10 * time.Minute

// ProjectWriter upserts projects from Notion data.
type ProjectWriter interface {
	UpsertByNotionPageID(ctx context.Context, p project.UpsertByNotionParams) (*project.Project, error)
	UpdateLastActivity(ctx context.Context, notionPageID string) error
	ArchiveByNotionPageID(ctx context.Context, notionPageID string) (int64, error)
	ArchiveOrphanNotion(ctx context.Context, activeIDs []string) (int64, error)
}

// GoalWriter upserts goals from Notion data.
type GoalWriter interface {
	UpsertByNotionPageID(ctx context.Context, p goal.UpsertByNotionParams) (*goal.Goal, error)
	ArchiveByNotionPageID(ctx context.Context, notionPageID string) (int64, error)
	ArchiveOrphanNotion(ctx context.Context, activeIDs []string) (int64, error)
}

// TaskWriter upserts tasks from Notion data.
type TaskWriter interface {
	UpsertByNotionPageID(ctx context.Context, p task.UpsertByNotionParams) (*task.Task, error)
	ArchiveByNotionPageID(ctx context.Context, notionPageID string) (int64, error)
	ArchiveOrphanNotion(ctx context.Context, activeIDs []string) (int64, error)
}

// JobSubmitter submits flow runs for async processing.
type JobSubmitter interface {
	Submit(ctx context.Context, flowName string, input json.RawMessage, contentID *uuid.UUID) error
}

// EventRecorder records activity events for Notion sync tracking.
type EventRecorder interface {
	CreateEvent(ctx context.Context, p activity.RecordParams) (int64, error)
}

// ProjectSlugResolver resolves a Notion page ID to a project slug.
type ProjectSlugResolver interface {
	SlugByNotionPageID(ctx context.Context, notionPageID string) (string, error)
}

// ProjectIDResolver resolves a Notion page ID to a local project UUID.
type ProjectIDResolver interface {
	IDByNotionPageID(ctx context.Context, notionPageID string) (uuid.UUID, error)
}

// Handler handles Notion webhook events.
type Handler struct {
	client        *Client
	store         *Store
	sourceCache   *ristretto.Cache[string, string]
	projects      ProjectWriter
	goals         GoalWriter
	tasks         TaskWriter
	jobs          JobSubmitter
	events        EventRecorder
	projectSlugs  ProjectSlugResolver
	projectIDs    ProjectIDResolver
	dedup         *webhook.DeduplicationCache
	webhookSecret string
	logger        *slog.Logger

	// bgWg tracks background goroutines launched by SyncRole for graceful shutdown.
	bgWg sync.WaitGroup

	// syncInFlight tracks page IDs currently being synced to prevent
	// concurrent syncs of the same page (e.g. webhook vs cron race).
	syncInFlight sync.Map
}

// HandlerOption configures optional Handler dependencies.
type HandlerOption func(*Handler)

// WithEventRecorder sets the activity event recorder for Notion sync tracking.
func WithEventRecorder(e EventRecorder) HandlerOption {
	return func(h *Handler) { h.events = e }
}

// WithProjectSlugResolver sets the project slug resolver for task event project attribution.
func WithProjectSlugResolver(r ProjectSlugResolver) HandlerOption {
	return func(h *Handler) { h.projectSlugs = r }
}

// WithProjectIDResolver sets the project ID resolver for task → project FK resolution.
func WithProjectIDResolver(r ProjectIDResolver) HandlerOption {
	return func(h *Handler) { h.projectIDs = r }
}

// WithDedup sets the deduplication cache for webhook replay protection.
func WithDedup(c *webhook.DeduplicationCache) HandlerOption {
	return func(h *Handler) { h.dedup = c }
}

// NewHandler returns a Notion webhook Handler.
func NewHandler(
	client *Client,
	store *Store,
	sourceCache *ristretto.Cache[string, string],
	projects ProjectWriter,
	goals GoalWriter,
	tasks TaskWriter,
	jobs JobSubmitter,
	webhookSecret string,
	logger *slog.Logger,
	opts ...HandlerOption,
) *Handler {
	h := &Handler{
		client:        client,
		store:         store,
		sourceCache:   sourceCache,
		projects:      projects,
		goals:         goals,
		tasks:         tasks,
		jobs:          jobs,
		webhookSecret: webhookSecret,
		logger:        logger,
	}
	for _, opt := range opts {
		opt(h)
	}
	if h.dedup == nil {
		logger.Warn("notion handler created without dedup cache — replay protection disabled")
	}
	return h
}

// Wait blocks until all background goroutines (SyncRole) complete.
// Call during graceful shutdown.
func (h *Handler) Wait() {
	h.bgWg.Wait()
}

// trySync attempts to sync a page, skipping if another goroutine is already syncing it.
// Returns ErrSkipped if the page is already being synced.
func (h *Handler) trySync(ctx context.Context, pageID string, syncFn func(context.Context, string) error) error {
	if _, loaded := h.syncInFlight.LoadOrStore(pageID, struct{}{}); loaded {
		h.logger.Debug("skipping concurrent sync for page", "page_id", pageID)
		return ErrSkipped
	}
	defer h.syncInFlight.Delete(pageID)
	return syncFn(ctx, pageID)
}

// Webhook handles POST /api/webhook/notion.
func (h *Handler) Webhook(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("reading notion webhook body", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Handle Notion verification handshake.
	// Only allowed before the webhook secret is configured (initial setup).
	// Once the secret is set, this path is closed to prevent abuse.
	if h.webhookSecret == "" {
		var probe struct {
			VerificationToken string `json:"verification_token"`
		}
		if json.Unmarshal(body, &probe) == nil && probe.VerificationToken != "" {
			h.logger.Info("notion webhook verification handshake received")
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "not implemented", http.StatusNotImplemented)
		return
	}

	sig := r.Header.Get("X-Notion-Signature")
	if err := webhook.VerifySignature(body, sig, h.webhookSecret); err != nil {
		h.logger.Warn("invalid notion webhook signature")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		h.logger.Error("parsing notion webhook payload", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// replay protection: timestamp ±5min + entity dedup
	if h.dedup != nil {
		if payload.Timestamp == "" {
			h.logger.Warn("notion webhook missing timestamp, rejecting")
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := webhook.ValidateTimestamp(payload.Timestamp, 5*time.Minute); err != nil {
			h.logger.Warn("notion webhook timestamp rejected", "error", err)
			http.Error(w, "request expired", http.StatusBadRequest)
			return
		}
		dedupKey := payload.Entity.ID + "|" + payload.Timestamp
		if h.dedup.Seen(dedupKey) {
			h.logger.Warn("notion webhook replay detected",
				"entity_id", payload.Entity.ID,
				"timestamp", payload.Timestamp,
			)
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	role := h.resolveRole(r.Context(), payload.Data.Parent.DataSourceID)
	pageID := payload.Entity.ID

	h.logger.Info("notion webhook received",
		"type", payload.Type,
		"page_id", pageID,
		"data_source_id", payload.Data.Parent.DataSourceID,
		"role", role,
	)

	// All roles return 200 on error (best-effort) so Notion does not retry
	// endlessly. Errors are logged for alerting. The hourly SyncAll cron
	// acts as the safety net for any missed updates.
	var syncErr error
	switch role {
	case RoleProjects:
		syncErr = h.trySync(r.Context(), pageID, h.syncProject)
	case RoleTasks:
		syncErr = h.trySync(r.Context(), pageID, h.syncTask)
	case RoleBooks:
		syncErr = h.trySync(r.Context(), pageID, h.syncBook)
	case RoleGoals:
		syncErr = h.trySync(r.Context(), pageID, h.syncGoal)
	default:
		h.logger.Debug("notion webhook from unknown database, skipping",
			"data_source_id", payload.Data.Parent.DataSourceID,
		)
	}

	if syncErr != nil && !errors.Is(syncErr, ErrSkipped) {
		h.logger.Error("syncing from notion webhook", "role", role, "page_id", pageID, "error", syncErr)
	}

	w.WriteHeader(http.StatusOK)
}

// syncTarget defines a role-specific sync operation for use in SyncAll/SyncRole.
type syncTarget struct {
	role          string
	syncFn        func(ctx context.Context, result DatabaseQueryResult) error
	archiveOrphan func(ctx context.Context, activeIDs []string) (int64, error)
}

// SyncAll fetches all pages from configured Notion databases and upserts them.
// Uses QueryDataSource to get full page data in bulk, avoiding per-page API calls.
// Used by the hourly cron to catch any missed webhook events.
func (h *Handler) SyncAll(ctx context.Context) {
	targets := h.syncTargets()
	var synced, failed int
	for _, t := range targets {
		s, f := h.syncByRole(ctx, t)
		synced += s
		failed += f
	}
	h.logger.Info("notion sync: complete", "synced", synced, "failed", failed)
}

// SyncRole syncs only the specified role's Notion database.
// Used when a source is created or its role is changed.
func (h *Handler) SyncRole(ctx context.Context, role string) {
	for _, t := range h.syncTargets() {
		if t.role == role {
			s, f := h.syncByRole(ctx, t)
			h.logger.Info("notion sync role: complete", "role", role, "synced", s, "failed", f)
			return
		}
	}
	h.logger.Warn("notion sync role: unknown role", "role", role)
}

// syncRoleTimeout bounds SyncRoleAsync execution so a hung Notion API
// cannot block shutdown indefinitely via bgWg.Wait(). Matches the cron
// hourly sync's 5-minute timeout.
const syncRoleTimeout = 5 * time.Minute

// SyncRoleAsync launches SyncRole in a tracked background goroutine.
// Detaches from the caller's context (which may be an HTTP request) so the
// sync outlives the request, then applies syncRoleTimeout to bound execution.
func (h *Handler) SyncRoleAsync(ctx context.Context, role string) {
	h.bgWg.Go(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), syncRoleTimeout)
		defer cancel()
		h.SyncRole(ctx, role)
	})
}

// syncTargets builds the list of role-specific sync operations.
func (h *Handler) syncTargets() []syncTarget {
	return []syncTarget{
		{
			role:          RoleProjects,
			syncFn:        h.syncProjectFromResult,
			archiveOrphan: h.projects.ArchiveOrphanNotion,
		},
		{
			role:          RoleGoals,
			syncFn:        h.syncGoalFromResult,
			archiveOrphan: h.goals.ArchiveOrphanNotion,
		},
		{
			role:          RoleTasks,
			syncFn:        h.syncTaskFromResult,
			archiveOrphan: h.tasks.ArchiveOrphanNotion,
		},
	}
}

// staleSyncThreshold is the minimum time since last sync before a full sync is warranted.
// If a source was synced less than this duration ago, syncByRole skips it.
const staleSyncThreshold = 10 * time.Minute

// syncByRole runs a single role sync: query data source, upsert pages, archive orphans.
// Skips the sync if the source was synced less than staleSyncThreshold ago.
func (h *Handler) syncByRole(ctx context.Context, t syncTarget) (synced, failed int) {
	src, err := h.store.SourceByRole(ctx, t.role)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			h.logger.Error("notion sync: looking up source", "role", t.role, "error", err)
		}
		return 0, 0
	}

	// Skip if recently synced (avoids redundant API calls on rapid restarts)
	if src.LastSyncedAt != nil && time.Since(*src.LastSyncedAt) < staleSyncThreshold {
		h.logger.Info("notion sync: skipping (recently synced)",
			"role", t.role,
			"last_synced", src.LastSyncedAt,
		)
		return 0, 0
	}

	h.logger.Info("notion sync: starting", "role", t.role, "database_id", src.DatabaseID)
	results, err := h.client.QueryDataSource(ctx, src.DatabaseID, nil)
	if err != nil {
		h.logger.Error("notion sync: querying database", "role", t.role, "error", err)
		return 0, 0
	}

	h.logger.Info("notion sync: fetched pages", "role", t.role, "count", len(results))
	activeIDs := make([]string, 0, len(results))
	for _, r := range results {
		// Skip if a webhook is actively syncing this page to avoid
		// overwriting fresh webhook data with potentially stale cron data.
		if _, busy := h.syncInFlight.LoadOrStore(r.ID, struct{}{}); busy {
			h.logger.Debug("notion sync: skipping page (webhook in progress)",
				"role", t.role, "page_id", r.ID)
			activeIDs = append(activeIDs, r.ID) // still active for orphan check
			continue
		}
		if err := t.syncFn(ctx, r); err != nil {
			h.syncInFlight.Delete(r.ID)
			h.logger.Error("notion sync: syncing page", "role", t.role, "page_id", r.ID, "error", err)
			failed++
			continue
		}
		h.syncInFlight.Delete(r.ID)
		activeIDs = append(activeIDs, r.ID)
		synced++
	}

	if len(results) > 0 && len(activeIDs) == 0 {
		h.logger.Warn("notion sync: all page syncs failed, skipping orphan archive",
			"role", t.role, "total", len(results), "failed", failed)
	}

	if archived, archErr := t.archiveOrphan(ctx, activeIDs); archErr != nil {
		h.logger.Error("notion sync: archiving orphans", "role", t.role, "error", archErr)
	} else if archived > 0 {
		h.logger.Info("notion sync: archived orphans", "role", t.role, "count", archived)
	}

	if updateErr := h.store.UpdateLastSynced(ctx, src.ID); updateErr != nil {
		h.logger.Error("notion sync: updating last_synced_at", "role", t.role, "error", updateErr)
	}

	return synced, failed
}

// resolveRole looks up the role for a webhook data source ID.
// Uses Ristretto cache with TTL to avoid querying DB on every webhook.
func (h *Handler) resolveRole(ctx context.Context, dataSourceID string) string {
	if dataSourceID == "" {
		return ""
	}

	// check cache first
	if role, ok := h.sourceCache.Get(dataSourceID); ok {
		return role
	}

	// cache miss — query store
	src, err := h.store.SourceByDatabaseID(ctx, dataSourceID)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			h.logger.Error("resolving notion source role", "database_id", dataSourceID, "error", err)
		}
		// cache empty string to avoid repeated DB misses for unknown sources
		h.sourceCache.SetWithTTL(dataSourceID, "", 1, sourceCacheTTL)
		return ""
	}

	role := ""
	if src.Role != nil {
		role = *src.Role
	}
	h.sourceCache.SetWithTTL(dataSourceID, role, 1, sourceCacheTTL)
	return role
}
