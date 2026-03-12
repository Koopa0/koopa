package notion

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/webhook"
)

// ProjectWriter upserts projects from Notion data.
type ProjectWriter interface {
	UpsertByNotionPageID(ctx context.Context, p project.UpsertByNotionParams) (*project.Project, error)
	UpdateLastActivity(ctx context.Context, notionPageID string) error
}

// GoalWriter upserts goals from Notion data.
type GoalWriter interface {
	UpsertByNotionPageID(ctx context.Context, p goal.UpsertByNotionParams) (*goal.Goal, error)
}

// JobSubmitter submits flow runs for async processing.
type JobSubmitter interface {
	Submit(ctx context.Context, flowName string, input json.RawMessage, contentID *uuid.UUID) error
}

// Handler handles Notion webhook events.
type Handler struct {
	client   *Client
	projects ProjectWriter
	goals    GoalWriter
	jobs     JobSubmitter
	dedup    *webhook.DeduplicationCache
	config   Config
	logger   *slog.Logger
}

// NewHandler returns a Notion webhook Handler.
func NewHandler(client *Client, projects ProjectWriter, goals GoalWriter, jobs JobSubmitter, cfg Config, logger *slog.Logger) *Handler {
	return &Handler{
		client:   client,
		projects: projects,
		goals:    goals,
		jobs:     jobs,
		config:   cfg,
		logger:   logger,
	}
}

// SetDedup sets the deduplication cache for webhook replay protection.
func (h *Handler) SetDedup(c *webhook.DeduplicationCache) {
	h.dedup = c
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

	if h.config.WebhookSecret == "" {
		http.Error(w, "not implemented", http.StatusNotImplemented)
		return
	}

	sig := r.Header.Get("X-Notion-Signature")
	if err := webhook.VerifySignature(body, sig, h.config.WebhookSecret); err != nil {
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

	db := h.routeDatabase(payload.Data.Parent.DataSourceID)
	pageID := payload.Entity.ID

	h.logger.Info("notion webhook received",
		"type", payload.Type,
		"page_id", pageID,
		"data_source_id", payload.Data.Parent.DataSourceID,
		"route", db,
	)

	switch db {
	case dbProjects:
		if err := h.syncProject(r.Context(), pageID); err != nil {
			h.logger.Error("syncing project from notion", "page_id", pageID, "error", err)
			http.Error(w, "sync failed", http.StatusInternalServerError)
			return
		}
	case dbTasks:
		if err := h.syncTaskActivity(r.Context(), pageID); err != nil {
			h.logger.Error("syncing task activity from notion", "page_id", pageID, "error", err)
			// task activity is best-effort, still return 200
		}
	case dbBooks:
		if err := h.syncBook(r.Context(), pageID); err != nil {
			h.logger.Error("syncing book from notion", "page_id", pageID, "error", err)
			// book sync is best-effort, still return 200
		}
	case dbGoals:
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
	if h.config.APIKey == "" {
		h.logger.Debug("notion sync: no API key configured, skipping")
		return
	}

	var synced, failed int

	// sync projects
	if h.config.ProjectsDB != "" {
		pageIDs, err := h.client.QueryPageIDs(ctx, h.config.ProjectsDB)
		if err != nil {
			h.logger.Error("notion sync: querying projects db", "error", err)
		} else {
			for _, id := range pageIDs {
				if err := h.syncProject(ctx, id); err != nil {
					h.logger.Error("notion sync: syncing project", "page_id", id, "error", err)
					failed++
					continue
				}
				synced++
			}
		}
	}

	// sync goals
	if h.config.GoalsDB != "" {
		pageIDs, err := h.client.QueryPageIDs(ctx, h.config.GoalsDB)
		if err != nil {
			h.logger.Error("notion sync: querying goals db", "error", err)
		} else {
			for _, id := range pageIDs {
				if err := h.syncGoal(ctx, id); err != nil {
					h.logger.Error("notion sync: syncing goal", "page_id", id, "error", err)
					failed++
					continue
				}
				synced++
			}
		}
	}

	h.logger.Info("notion sync: complete", "synced", synced, "failed", failed)
}

// routeDatabase matches a webhook data source ID to a known database.
func (h *Handler) routeDatabase(dataSourceID string) database {
	if dataSourceID == "" {
		return dbUnknown
	}
	switch dataSourceID {
	case h.config.ProjectsDB:
		return dbProjects
	case h.config.TasksDB:
		return dbTasks
	case h.config.BooksDB:
		return dbBooks
	case h.config.GoalsDB:
		return dbGoals
	default:
		return dbUnknown
	}
}
