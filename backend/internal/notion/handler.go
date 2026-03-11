package notion

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

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

// routeDatabase matches a data source ID to a known database.
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
