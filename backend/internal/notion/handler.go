package notion

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
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
	ArchiveOrphanNotion(ctx context.Context, activeIDs []string) (int64, error)
}

// GoalWriter upserts goals from Notion data.
type GoalWriter interface {
	UpsertByNotionPageID(ctx context.Context, p goal.UpsertByNotionParams) (*goal.Goal, error)
	ArchiveOrphanNotion(ctx context.Context, activeIDs []string) (int64, error)
}

// TaskWriter upserts tasks from Notion data.
type TaskWriter interface {
	UpsertByNotionPageID(ctx context.Context, p task.UpsertByNotionParams) (*task.Task, error)
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
	return h
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
	// NOTE: Notion does not sign the verification request, so HMAC check is skipped here.
	var probe struct {
		VerificationToken string `json:"verification_token"`
	}
	if json.Unmarshal(body, &probe) == nil && probe.VerificationToken != "" {
		h.logger.Info("notion webhook verification handshake received")
		w.WriteHeader(http.StatusOK)
		return
	}

	if h.webhookSecret == "" {
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
		if payload.Timestamp != "" {
			if err := webhook.ValidateTimestamp(payload.Timestamp, 5*time.Minute); err != nil {
				h.logger.Warn("notion webhook timestamp rejected", "error", err)
				http.Error(w, "request expired", http.StatusBadRequest)
				return
			}
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

	switch role {
	case RoleProjects:
		if err := h.syncProject(r.Context(), pageID); err != nil {
			h.logger.Error("syncing project from notion", "page_id", pageID, "error", err)
			http.Error(w, "sync failed", http.StatusInternalServerError)
			return
		}
	case RoleTasks:
		if err := h.syncTask(r.Context(), pageID); err != nil {
			h.logger.Error("syncing task from notion", "page_id", pageID, "error", err)
			// task sync is best-effort, still return 200
		}
	case RoleBooks:
		if err := h.syncBook(r.Context(), pageID); err != nil {
			h.logger.Error("syncing book from notion", "page_id", pageID, "error", err)
			// book sync is best-effort, still return 200
		}
	case RoleGoals:
		if err := h.syncGoal(r.Context(), pageID); err != nil {
			h.logger.Error("syncing goal from notion", "page_id", pageID, "error", err)
			// goal sync is best-effort, still return 200
		}
	default:
		h.logger.Debug("notion webhook from unknown database, skipping",
			"data_source_id", payload.Data.Parent.DataSourceID,
		)
	}

	w.WriteHeader(http.StatusOK)
}

// SyncAll fetches all pages from configured Notion databases and upserts them.
// Used by the hourly cron to catch any missed webhook events.
func (h *Handler) SyncAll(ctx context.Context) {
	var synced, failed int

	// sync projects
	if src, err := h.store.SourceByRole(ctx, RoleProjects); err == nil {
		h.logger.Info("notion sync: starting projects", "database_id", src.DatabaseID)
		pageIDs, err := h.client.QueryPageIDs(ctx, src.DatabaseID)
		if err != nil {
			h.logger.Error("notion sync: querying projects db", "error", err)
		} else {
			h.logger.Info("notion sync: fetched project pages", "count", len(pageIDs))
			for _, id := range pageIDs {
				if err := h.syncProject(ctx, id); err != nil {
					h.logger.Error("notion sync: syncing project", "page_id", id, "error", err)
					failed++
					continue
				}
				synced++
			}
			// archive projects whose notion_page_id is no longer in Notion
			if archived, err := h.projects.ArchiveOrphanNotion(ctx, pageIDs); err != nil {
				h.logger.Error("notion sync: archiving orphan projects", "error", err)
			} else if archived > 0 {
				h.logger.Info("notion sync: archived orphan projects", "count", archived)
			}
			// best-effort: update last_synced_at
			if updateErr := h.store.UpdateLastSynced(ctx, src.ID); updateErr != nil {
				h.logger.Error("notion sync: updating last_synced_at for projects", "error", updateErr)
			}
		}
	} else if !errors.Is(err, ErrNotFound) {
		h.logger.Error("notion sync: looking up projects source", "error", err)
	}

	// sync goals
	if src, err := h.store.SourceByRole(ctx, RoleGoals); err == nil {
		h.logger.Info("notion sync: starting goals", "database_id", src.DatabaseID)
		pageIDs, err := h.client.QueryPageIDs(ctx, src.DatabaseID)
		if err != nil {
			h.logger.Error("notion sync: querying goals db", "error", err)
		} else {
			h.logger.Info("notion sync: fetched goal pages", "count", len(pageIDs))
			for _, id := range pageIDs {
				if err := h.syncGoal(ctx, id); err != nil {
					h.logger.Error("notion sync: syncing goal", "page_id", id, "error", err)
					failed++
					continue
				}
				synced++
			}
			// archive goals whose notion_page_id is no longer in Notion
			if archived, err := h.goals.ArchiveOrphanNotion(ctx, pageIDs); err != nil {
				h.logger.Error("notion sync: archiving orphan goals", "error", err)
			} else if archived > 0 {
				h.logger.Info("notion sync: archived orphan goals", "count", archived)
			}
			if updateErr := h.store.UpdateLastSynced(ctx, src.ID); updateErr != nil {
				h.logger.Error("notion sync: updating last_synced_at for goals", "error", updateErr)
			}
		}
	} else if !errors.Is(err, ErrNotFound) {
		h.logger.Error("notion sync: looking up goals source", "error", err)
	}

	// sync tasks
	if src, err := h.store.SourceByRole(ctx, RoleTasks); err == nil {
		h.logger.Info("notion sync: starting tasks", "database_id", src.DatabaseID)
		pageIDs, err := h.client.QueryPageIDs(ctx, src.DatabaseID)
		if err != nil {
			h.logger.Error("notion sync: querying tasks db", "error", err)
		} else {
			h.logger.Info("notion sync: fetched task pages", "count", len(pageIDs))
			for _, id := range pageIDs {
				if err := h.syncTask(ctx, id); err != nil {
					h.logger.Error("notion sync: syncing task", "page_id", id, "error", err)
					failed++
					continue
				}
				synced++
			}
			// archive tasks whose notion_page_id is no longer in Notion
			if archived, err := h.tasks.ArchiveOrphanNotion(ctx, pageIDs); err != nil {
				h.logger.Error("notion sync: archiving orphan tasks", "error", err)
			} else if archived > 0 {
				h.logger.Info("notion sync: archived orphan tasks", "count", archived)
			}
			if updateErr := h.store.UpdateLastSynced(ctx, src.ID); updateErr != nil {
				h.logger.Error("notion sync: updating last_synced_at for tasks", "error", updateErr)
			}
		}
	} else if !errors.Is(err, ErrNotFound) {
		h.logger.Error("notion sync: looking up tasks source", "error", err)
	}

	h.logger.Info("notion sync: complete", "synced", synced, "failed", failed)
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
