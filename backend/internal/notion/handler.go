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
	"github.com/koopa0/blog-backend/internal/ai/exec"
	"github.com/koopa0/blog-backend/internal/event"
	"github.com/koopa0/blog-backend/internal/webhook"
)

// sourceCacheTTL is how long a database_id -> role mapping stays in cache.
const sourceCacheTTL = 10 * time.Minute

// staleSyncThreshold is the minimum time since last sync before a full sync is warranted.
// If a source was synced less than this duration ago, syncByRole skips it.
const staleSyncThreshold = 10 * time.Minute

// syncRoleTimeout bounds SyncRoleAsync execution so a hung Notion API
// cannot block shutdown indefinitely via bgWg.Wait(). Matches the cron
// hourly sync's 5-minute timeout.
const syncRoleTimeout = 5 * time.Minute

// ProjectSyncInput holds extracted Notion properties for project sync.
// All fields are primitives -- no json.RawMessage, no notion-specific types.
type ProjectSyncInput struct {
	PageID      string
	Title       string
	Status      string // raw Notion status name (e.g. "Doing", "Planned")
	Description string
	Area        string     // resolved from Tag relation
	GoalID      *uuid.UUID // resolved from Goal relation
	Deadline    *time.Time
}

// GoalSyncInput holds extracted Notion properties for goal sync.
type GoalSyncInput struct {
	PageID   string
	Title    string
	Status   string // raw Notion status name (e.g. "Dream", "Active")
	Area     string // resolved from Tag relation
	Deadline *time.Time
}

// TaskSyncInput holds extracted Notion properties for task sync.
type TaskSyncInput struct {
	PageID        string
	Title         string
	Status        string // raw Notion status name (e.g. "To Do", "Doing")
	Due           *time.Time
	Energy        string
	Priority      string
	RecurInterval *int32
	RecurUnit     string
	MyDay         bool
	Description   string
	ProjectPageID string // resolved project Notion page ID (with parent-task fallback)
}

// ProjectSyncFunc upserts a project from extracted Notion properties.
// Wired in main.go to call project.Store methods.
type ProjectSyncFunc func(ctx context.Context, input *ProjectSyncInput) error

// GoalSyncFunc upserts a goal from extracted Notion properties.
// Wired in main.go to call goal.Store methods.
type GoalSyncFunc func(ctx context.Context, input *GoalSyncInput) error

// TaskSyncFunc upserts a task from extracted Notion properties.
// Wired in main.go to call task.Store methods.
type TaskSyncFunc func(ctx context.Context, input *TaskSyncInput) error

// Handler handles Notion webhook events.
type Handler struct {
	client      *Client
	store       *Store
	sourceCache *ristretto.Cache[string, string]

	// Archivers handle trash/archive and orphan cleanup per role.
	projectArchiver Archiver
	goalArchiver    Archiver
	taskArchiver    Archiver

	// Resolvers provide cross-entity lookups without importing feature packages.
	projectResolver ProjectResolver
	goalResolver    GoalResolver

	// Sync callbacks: notion extracts properties, feature packages own the upsert.
	// Wired in main.go to call feature.Store methods.
	projectSync ProjectSyncFunc
	goalSync    GoalSyncFunc
	taskSync    TaskSyncFunc

	jobs          *exec.Runner
	events        *activity.Store
	dedup         *webhook.DeduplicationCache
	bus           *event.Bus
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
func WithEventRecorder(e *activity.Store) HandlerOption {
	return func(h *Handler) { h.events = e }
}

// WithProjectResolver sets the project resolver for slug and ID lookups.
func WithProjectResolver(pr ProjectResolver) HandlerOption {
	return func(h *Handler) { h.projectResolver = pr }
}

// WithGoalResolver sets the goal ID resolver for project -> goal FK resolution.
func WithGoalResolver(gr GoalResolver) HandlerOption {
	return func(h *Handler) { h.goalResolver = gr }
}

// WithDedup sets the deduplication cache for webhook replay protection.
func WithDedup(c *webhook.DeduplicationCache) HandlerOption {
	return func(h *Handler) { h.dedup = c }
}

// WithEventBus sets the event bus for emitting cross-cutting events.
func WithEventBus(b *event.Bus) HandlerOption {
	return func(h *Handler) { h.bus = b }
}

// WithProjectSync sets the project archiver and sync callback.
func WithProjectSync(archiver Archiver, syncFn ProjectSyncFunc) HandlerOption {
	return func(h *Handler) {
		h.projectArchiver = archiver
		h.projectSync = syncFn
	}
}

// WithGoalSync sets the goal archiver and sync callback.
func WithGoalSync(archiver Archiver, syncFn GoalSyncFunc) HandlerOption {
	return func(h *Handler) {
		h.goalArchiver = archiver
		h.goalSync = syncFn
	}
}

// WithTaskSync sets the task archiver and sync callback.
func WithTaskSync(archiver Archiver, syncFn TaskSyncFunc) HandlerOption {
	return func(h *Handler) {
		h.taskArchiver = archiver
		h.taskSync = syncFn
	}
}

// NewHandler returns a Notion webhook Handler.
func NewHandler(
	client *Client,
	store *Store,
	sourceCache *ristretto.Cache[string, string],
	jobs *exec.Runner,
	webhookSecret string,
	logger *slog.Logger,
	opts ...HandlerOption,
) *Handler {
	h := &Handler{
		client:        client,
		store:         store,
		sourceCache:   sourceCache,
		jobs:          jobs,
		webhookSecret: webhookSecret,
		logger:        logger,
	}
	for _, opt := range opts {
		opt(h)
	}
	if h.dedup == nil {
		logger.Warn("notion handler created without dedup cache -- replay protection disabled")
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
		h.handleVerificationHandshake(w, body)
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

	if rejected := h.rejectReplay(w, &payload); rejected {
		return
	}

	h.dispatchWebhookSync(r.Context(), w, &payload)
}

// handleVerificationHandshake responds to Notion's initial webhook verification probe.
func (h *Handler) handleVerificationHandshake(w http.ResponseWriter, body []byte) {
	var probe struct {
		VerificationToken string `json:"verification_token"`
	}
	if json.Unmarshal(body, &probe) == nil && probe.VerificationToken != "" {
		h.logger.Info("notion webhook verification handshake received")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// rejectReplay performs timestamp and dedup checks. Returns true if the request was rejected.
func (h *Handler) rejectReplay(w http.ResponseWriter, payload *WebhookPayload) bool {
	if h.dedup == nil {
		return false
	}
	if payload.Timestamp == "" {
		h.logger.Warn("notion webhook missing timestamp, rejecting")
		http.Error(w, "bad request", http.StatusBadRequest)
		return true
	}
	if err := webhook.ValidateTimestamp(payload.Timestamp, 5*time.Minute); err != nil {
		h.logger.Warn("notion webhook timestamp rejected", "error", err)
		http.Error(w, "request expired", http.StatusBadRequest)
		return true
	}
	dedupKey := payload.Entity.ID + "|" + payload.Timestamp
	if h.dedup.Seen(dedupKey) {
		h.logger.Warn("notion webhook replay detected",
			"entity_id", payload.Entity.ID,
			"timestamp", payload.Timestamp,
		)
		w.WriteHeader(http.StatusOK)
		return true
	}
	return false
}

// dispatchWebhookSync routes a validated webhook payload to the correct sync handler.
func (h *Handler) dispatchWebhookSync(ctx context.Context, w http.ResponseWriter, payload *WebhookPayload) {
	role := h.resolveRole(ctx, payload.Data.Parent.DataSourceID)
	pageID := payload.Entity.ID

	h.logger.Info("notion webhook received",
		"type", payload.Type,
		"page_id", pageID,
		"data_source_id", payload.Data.Parent.DataSourceID,
		"role", role,
	)

	var syncErr error
	switch role {
	case RoleProjects:
		syncErr = h.trySync(ctx, pageID, h.syncProject)
	case RoleTasks:
		syncErr = h.trySync(ctx, pageID, h.syncTask)
	case RoleBooks:
		syncErr = h.trySync(ctx, pageID, h.syncBook)
	case RoleGoals:
		syncErr = h.trySync(ctx, pageID, h.syncGoal)
	default:
		h.logger.Debug("notion webhook from unknown database, skipping",
			"data_source_id", payload.Data.Parent.DataSourceID,
		)
	}

	if syncErr != nil && !errors.Is(syncErr, ErrSkipped) {
		h.logger.Error("syncing from notion webhook", "role", role, "page_id", pageID, "error", syncErr)
	}

	if syncErr == nil && role != "" {
		h.emitPageUpdated(ctx, pageID, role)
	}

	w.WriteHeader(http.StatusOK)
}

// syncTarget defines a role-specific sync operation for use in SyncAll/SyncRole.
type syncTarget struct {
	role          string
	syncFn        func(ctx context.Context, result DatabaseQueryResult) error
	archiveOrphan func(ctx context.Context, activeIDs []string) (int64, error)
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

	// cache miss -- query store
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

// emitPageUpdated emits a NotionPageUpdated event on the bus (best-effort).
// If no bus is configured, this is a no-op.
func (h *Handler) emitPageUpdated(ctx context.Context, pageID, role string) {
	if h.bus == nil {
		return
	}
	if err := h.bus.Emit(ctx, event.NotionPageUpdated, map[string]any{
		"page_id": pageID,
		"role":    role,
	}); err != nil {
		h.logger.Warn("emitting notion page updated event", "error", err) // best-effort
	}
}
