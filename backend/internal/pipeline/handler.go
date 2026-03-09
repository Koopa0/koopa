package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/obsidian"
)

// ContentWriter creates or updates content in the database.
type ContentWriter interface {
	ContentBySlug(ctx context.Context, slug string) (*content.Content, error)
	CreateContent(ctx context.Context, p content.CreateParams) (*content.Content, error)
	UpdateContent(ctx context.Context, id uuid.UUID, p content.UpdateParams) (*content.Content, error)
	PublishContent(ctx context.Context, id uuid.UUID) (*content.Content, error)
}

// TopicLookup resolves a topic slug to a UUID.
type TopicLookup interface {
	TopicIDBySlug(ctx context.Context, slug string) (uuid.UUID, error)
}

// topicLookupAdapter adapts a *topic.Store to the TopicLookup interface.
type topicLookupAdapter struct {
	fn func(ctx context.Context, slug string) (uuid.UUID, error)
}

func (a *topicLookupAdapter) TopicIDBySlug(ctx context.Context, slug string) (uuid.UUID, error) {
	return a.fn(ctx, slug)
}

// GitHubFetcher retrieves raw file content from a GitHub repository.
type GitHubFetcher interface {
	FileContent(ctx context.Context, path string) ([]byte, error)
}

// Handler handles pipeline and webhook HTTP requests.
type Handler struct {
	content       ContentWriter
	topics        TopicLookup
	fetcher       GitHubFetcher
	webhookSecret string
	logger        *slog.Logger
}

// NewHandler returns a pipeline Handler.
func NewHandler(cw ContentWriter, tl TopicLookup, fetcher GitHubFetcher, webhookSecret string, logger *slog.Logger) *Handler {
	return &Handler{
		content:       cw,
		topics:        tl,
		fetcher:       fetcher,
		webhookSecret: webhookSecret,
		logger:        logger,
	}
}

// NewTopicLookup creates a TopicLookup from a function that returns a topic with an ID.
func NewTopicLookup(fn func(ctx context.Context, slug string) (uuid.UUID, error)) TopicLookup {
	return &topicLookupAdapter{fn: fn}
}

// Sync handles POST /api/pipeline/sync.
func (h *Handler) Sync(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// Collect handles POST /api/pipeline/collect.
func (h *Handler) Collect(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// Generate handles POST /api/pipeline/generate.
func (h *Handler) Generate(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// Digest handles POST /api/pipeline/digest.
func (h *Handler) Digest(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// WebhookObsidian handles POST /api/webhook/obsidian.
func (h *Handler) WebhookObsidian(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// WebhookNotion handles POST /api/webhook/notion.
func (h *Handler) WebhookNotion(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// WebhookGithub handles POST /api/webhook/github.
func (h *Handler) WebhookGithub(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("reading webhook body", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	sig := r.Header.Get("X-Hub-Signature-256")
	if err := VerifySignature(body, sig, h.webhookSecret); err != nil {
		h.logger.Warn("invalid webhook signature")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// only process push events
	if r.Header.Get("X-GitHub-Event") != "push" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var event PushEvent
	if err := json.Unmarshal(body, &event); err != nil {
		h.logger.Error("parsing push event", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// only process pushes to main branch
	if event.Ref != "refs/heads/main" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// filter markdown files under 10-Public-Content/
	files := filterPublicMarkdown(event.ChangedFiles())
	if len(files) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	// respond 202 immediately, process in background
	w.WriteHeader(http.StatusAccepted)

	go h.syncFiles(context.WithoutCancel(r.Context()), files)
}

// syncFiles fetches and upserts each markdown file.
func (h *Handler) syncFiles(ctx context.Context, files []string) {
	for _, path := range files {
		if err := h.syncFile(ctx, path); err != nil {
			h.logger.Error("syncing file", "path", path, "error", err)
			continue
		}
		h.logger.Info("synced file", "path", path)
	}
}

// syncFile fetches a single file from GitHub and upserts it as content.
func (h *Handler) syncFile(ctx context.Context, path string) error {
	raw, err := h.fetcher.FileContent(ctx, path)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", path, err)
	}

	parsed, body, err := obsidian.Parse(raw)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	slug := slugFromPath(path)

	// resolve topic IDs from parsed topic slugs
	topicIDs := h.resolveTopics(ctx, parsed.TopicSlugs)

	// determine content type
	contentType := content.TypeNote // default
	if parsed.ContentType != "" {
		contentType = content.Type(parsed.ContentType)
	}

	sourceType := content.SourceObsidian

	// check if content already exists
	existing, err := h.content.ContentBySlug(ctx, slug)
	if err == nil && existing != nil {
		// update existing content
		status := content.StatusDraft
		if parsed.Published {
			status = content.StatusPublished
		}
		_, err := h.content.UpdateContent(ctx, existing.ID, content.UpdateParams{
			Title:      &parsed.Title,
			Body:       &body,
			Type:       &contentType,
			Status:     &status,
			Tags:       parsed.Tags,
			TopicIDs:   topicIDs,
			SourceType: &sourceType,
			Source:     &path,
		})
		if err != nil {
			return fmt.Errorf("updating content %s: %w", slug, err)
		}

		// publish if the obsidian file is marked as published
		if parsed.Published && existing.Status != content.StatusPublished {
			if _, err := h.content.PublishContent(ctx, existing.ID); err != nil {
				return fmt.Errorf("publishing content %s: %w", slug, err)
			}
		}
		return nil
	}

	// create new content
	created, err := h.content.CreateContent(ctx, content.CreateParams{
		Slug:        slug,
		Title:       parsed.Title,
		Body:        body,
		Type:        contentType,
		Status:      content.StatusDraft,
		Tags:        parsed.Tags,
		TopicIDs:    topicIDs,
		SourceType:  &sourceType,
		Source:      &path,
		ReviewLevel: content.ReviewLight,
	})
	if err != nil {
		return fmt.Errorf("creating content %s: %w", slug, err)
	}

	// publish if the obsidian file is marked as published
	if parsed.Published {
		if _, err := h.content.PublishContent(ctx, created.ID); err != nil {
			return fmt.Errorf("publishing content %s: %w", slug, err)
		}
	}

	return nil
}

// resolveTopics looks up topic IDs for the given slugs, skipping unknown ones.
func (h *Handler) resolveTopics(ctx context.Context, slugs []string) []uuid.UUID {
	var ids []uuid.UUID
	for _, slug := range slugs {
		id, err := h.topics.TopicIDBySlug(ctx, slug)
		if err != nil {
			h.logger.Debug("topic not found, skipping", "slug", slug)
			continue
		}
		ids = append(ids, id)
	}
	return ids
}

// filterPublicMarkdown returns only .md files under 10-Public-Content/.
func filterPublicMarkdown(files []string) []string {
	var result []string
	for _, f := range files {
		if strings.HasPrefix(f, "10-Public-Content/") && strings.HasSuffix(f, ".md") {
			result = append(result, f)
		}
	}
	return result
}

// slugFromPath extracts a URL slug from a file path.
// Example: "10-Public-Content/my-post.md" → "my-post"
func slugFromPath(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, ".md")
}
