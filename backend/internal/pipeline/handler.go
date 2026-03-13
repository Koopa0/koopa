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
	"sync"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/obsidian"
	"github.com/koopa0/blog-backend/internal/webhook"
)

// ContentReader reads content by slug.
type ContentReader interface {
	ContentBySlug(ctx context.Context, slug string) (*content.Content, error)
}

// ContentWriter creates, updates, or archives content in the database.
type ContentWriter interface {
	CreateContent(ctx context.Context, p content.CreateParams) (*content.Content, error)
	UpdateContent(ctx context.Context, id uuid.UUID, p content.UpdateParams) (*content.Content, error)
	PublishContent(ctx context.Context, id uuid.UUID) (*content.Content, error)
	DeleteContent(ctx context.Context, id uuid.UUID) error
}

// TopicLookup resolves a topic slug to a UUID.
type TopicLookup interface {
	TopicIDBySlug(ctx context.Context, slug string) (uuid.UUID, error)
}

// topicLookupFunc wraps a function as a TopicLookup implementation.
type topicLookupFunc struct {
	fn func(ctx context.Context, slug string) (uuid.UUID, error)
}

func (a *topicLookupFunc) TopicIDBySlug(ctx context.Context, slug string) (uuid.UUID, error) {
	return a.fn(ctx, slug)
}

// JobSubmitter submits a flow run for async processing.
type JobSubmitter interface {
	Submit(ctx context.Context, flowName string, input json.RawMessage, contentID *uuid.UUID) error
}

// GitHubFetcher retrieves raw file content and directory listings from a GitHub repository.
type GitHubFetcher interface {
	FileContent(ctx context.Context, path string) ([]byte, error)
	ListDirectory(ctx context.Context, path string) ([]string, error)
}

// FeedCollector fetches new items from feeds and scores them.
type FeedCollector interface {
	FetchFeed(ctx context.Context, f feed.Feed) ([]uuid.UUID, error)
}

// FeedLister lists feeds by schedule.
type FeedLister interface {
	EnabledFeeds(ctx context.Context) ([]feed.Feed, error)
	EnabledFeedsBySchedule(ctx context.Context, schedule string) ([]feed.Feed, error)
}

// Reconciler runs the full reconciliation check.
type Reconciler interface {
	Run(ctx context.Context) error
}

// NotionSyncer fetches all Notion pages and upserts them locally.
type NotionSyncer interface {
	SyncAll(ctx context.Context)
}

// Handler handles pipeline and webhook HTTP requests.
type Handler struct {
	wg            sync.WaitGroup
	contentReader ContentReader
	contentWriter ContentWriter
	topics        TopicLookup
	fetcher       GitHubFetcher
	jobs          JobSubmitter
	collector     FeedCollector
	feeds         FeedLister
	reconciler    Reconciler
	notionSync    NotionSyncer
	dedup         *webhook.DeduplicationCache
	webhookSecret string
	obsidianRepo  string // "owner/repo" for Obsidian content sync
	logger        *slog.Logger
}

// NewHandler returns a pipeline Handler.
func NewHandler(cr ContentReader, cw ContentWriter, tl TopicLookup, fetcher GitHubFetcher, jobs JobSubmitter, webhookSecret, obsidianRepo string, logger *slog.Logger) *Handler {
	return &Handler{
		contentReader: cr,
		contentWriter: cw,
		topics:        tl,
		fetcher:       fetcher,
		jobs:          jobs,
		webhookSecret: webhookSecret,
		obsidianRepo:  obsidianRepo,
		logger:        logger,
	}
}

// SetCollector sets the feed collector and lister for the collect pipeline.
func (h *Handler) SetCollector(c FeedCollector, f FeedLister) {
	h.collector = c
	h.feeds = f
}

// SetReconciler sets the reconciler for manual sync endpoints.
func (h *Handler) SetReconciler(r Reconciler) {
	h.reconciler = r
}

// SetNotionSync sets the Notion syncer for full sync.
func (h *Handler) SetNotionSync(n NotionSyncer) {
	h.notionSync = n
}

// SetDedup sets the deduplication cache for webhook replay protection.
func (h *Handler) SetDedup(c *webhook.DeduplicationCache) {
	h.dedup = c
}

// Go runs fn in a tracked goroutine. Wait will block until fn returns.
func (h *Handler) Go(fn func()) {
	h.wg.Go(fn)
}

// Wait blocks until all in-flight background operations complete.
// Call during graceful shutdown to drain work before exiting.
func (h *Handler) Wait() {
	h.wg.Wait()
}

// NewTopicLookup creates a TopicLookup from a function that returns a topic with an ID.
func NewTopicLookup(fn func(ctx context.Context, slug string) (uuid.UUID, error)) TopicLookup {
	return &topicLookupFunc{fn: fn}
}

// Sync handles POST /api/pipeline/sync — full Obsidian sync from GitHub.
// Lists all .md files in 10-Public-Content/, compares with DB,
// and syncs any missing or updated files.
func (h *Handler) Sync(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`)
	h.wg.Go(func() {
		ctx := context.WithoutCancel(r.Context())
		h.SyncAllFromGitHub(ctx)
	})
}

// SyncAllFromGitHub lists 10-Public-Content/ on GitHub and syncs each file.
func (h *Handler) SyncAllFromGitHub(ctx context.Context) {
	slugs, err := h.fetcher.ListDirectory(ctx, "10-Public-Content")
	if err != nil {
		h.logger.Error("sync: listing github directory", "error", err)
		return
	}

	var synced, failed int
	for _, slug := range slugs {
		path := "10-Public-Content/" + slug + ".md"
		if err := h.syncFile(ctx, path); err != nil {
			h.logger.Error("sync: syncing file", "path", path, "error", err)
			failed++
			continue
		}
		synced++
	}

	h.logger.Info("sync: complete",
		"total", len(slugs),
		"synced", synced,
		"failed", failed,
	)
}

// NotionSync handles POST /api/pipeline/notion-sync — full Notion sync.
func (h *Handler) NotionSync(w http.ResponseWriter, r *http.Request) {
	if h.notionSync == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`)
	h.wg.Go(func() {
		ctx := context.WithoutCancel(r.Context())
		h.notionSync.SyncAll(ctx)
	})
}

// Reconcile handles POST /api/pipeline/reconcile — full Obsidian + Notion reconciliation.
func (h *Handler) Reconcile(w http.ResponseWriter, r *http.Request) {
	if h.reconciler == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`)
	h.wg.Go(func() {
		// Detach from HTTP request lifecycle; reconciler calls external APIs.
		ctx := context.WithoutCancel(r.Context())
		if err := h.reconciler.Run(ctx); err != nil {
			h.logger.Error("full reconciliation failed", "error", err)
		}
	})
}

// collectRequest is the optional request body for POST /api/pipeline/collect.
type collectRequest struct {
	Schedule string `json:"schedule"`
}

// Collect handles POST /api/pipeline/collect.
// When a schedule is provided, fetches enabled feeds for that schedule only.
// When no schedule is provided, fetches all enabled feeds.
func (h *Handler) Collect(w http.ResponseWriter, r *http.Request) {
	if h.collector == nil || h.feeds == nil {
		http.Error(w, "collector not configured", http.StatusNotImplemented)
		return
	}

	var schedule string
	if r.Body != nil && r.ContentLength > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var req collectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.Schedule != "" {
			schedule = req.Schedule
		}
	}

	var (
		feeds []feed.Feed
		err   error
	)
	if schedule != "" {
		feeds, err = h.feeds.EnabledFeedsBySchedule(r.Context(), schedule)
	} else {
		schedule = "all"
		feeds, err = h.feeds.EnabledFeeds(r.Context())
	}
	if err != nil {
		h.logger.Error("listing feeds for collect", "schedule", schedule, "error", err)
		http.Error(w, "failed to list feeds", http.StatusInternalServerError)
		return
	}

	// respond 202 immediately, collect in background
	w.WriteHeader(http.StatusAccepted)

	h.wg.Go(func() {
		h.collectFeeds(context.WithoutCancel(r.Context()), feeds, schedule)
	})
}

// collectFeeds fetches each feed and stores new items.
func (h *Handler) collectFeeds(ctx context.Context, feeds []feed.Feed, schedule string) {
	var totalNew int
	for _, f := range feeds {
		ids, err := h.collector.FetchFeed(ctx, f)
		if err != nil {
			h.logger.Error("collecting feed", "feed_id", f.ID, "feed_name", f.Name, "error", err)
			continue
		}
		totalNew += len(ids)
	}
	h.logger.Info("collect pipeline complete",
		"schedule", schedule,
		"feeds_count", len(feeds),
		"new_items", totalNew,
	)
}

// Generate handles POST /api/pipeline/generate.
func (h *Handler) Generate(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// digestRequest is the request body for POST /api/pipeline/digest.
type digestRequest struct {
	StartDate string `json:"start_date"` // YYYY-MM-DD
	EndDate   string `json:"end_date"`   // YYYY-MM-DD
}

// Digest handles POST /api/pipeline/digest.
// Submits a digest-generate flow job for the given date range.
func (h *Handler) Digest(w http.ResponseWriter, r *http.Request) {
	var req digestRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.StartDate == "" || req.EndDate == "" {
		http.Error(w, "start_date and end_date are required", http.StatusBadRequest)
		return
	}

	input, err := json.Marshal(req)
	if err != nil {
		h.logger.Error("marshaling digest input", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := h.jobs.Submit(r.Context(), "digest-generate", input, nil); err != nil {
		h.logger.Error("submitting digest-generate", "error", err)
		http.Error(w, "failed to submit digest job", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`) // best-effort
}

// bookmarkRequest is the request body for POST /api/pipeline/bookmark.
type bookmarkRequest struct {
	CollectedDataID string `json:"collected_data_id"`
}

// Bookmark handles POST /api/pipeline/bookmark.
// Submits a bookmark-generate flow for the given collected data.
func (h *Handler) Bookmark(w http.ResponseWriter, r *http.Request) {
	var req bookmarkRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if _, err := uuid.Parse(req.CollectedDataID); err != nil {
		http.Error(w, "invalid collected_data_id", http.StatusBadRequest)
		return
	}

	input, err := json.Marshal(req)
	if err != nil {
		h.logger.Error("marshaling bookmark input", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := h.jobs.Submit(r.Context(), "bookmark-generate", input, nil); err != nil {
		h.logger.Error("submitting bookmark-generate", "error", err)
		http.Error(w, "failed to submit bookmark job", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`) // best-effort
}

// WebhookGithub handles POST /api/webhook/github.
func (h *Handler) WebhookGithub(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("reading webhook body", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	sig := r.Header.Get("X-Hub-Signature-256")
	if err := webhook.VerifySignature(body, sig, h.webhookSecret); err != nil {
		h.logger.Warn("invalid webhook signature")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// replay protection: reject duplicate deliveries
	if h.dedup != nil {
		deliveryID := r.Header.Get("X-GitHub-Delivery")
		if deliveryID != "" && h.dedup.Seen(deliveryID) {
			h.logger.Warn("github webhook replay detected", "delivery_id", deliveryID)
			w.WriteHeader(http.StatusOK)
			return
		}
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

	// route: Obsidian repo → content sync, other repos → project-track
	if event.Repository.FullName != h.obsidianRepo {
		h.handleProjectTrack(w, r, event)
		return
	}

	// filter markdown files under 10-Public-Content/
	files := filterPublicMarkdown(event.ChangedFiles())
	removed := filterPublicMarkdown(event.RemovedFiles())

	if len(files) == 0 && len(removed) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	// respond 202 immediately, process in background
	w.WriteHeader(http.StatusAccepted)

	h.wg.Go(func() {
		ctx := context.WithoutCancel(r.Context())
		h.syncFiles(ctx, files)
		h.archiveRemovedFiles(ctx, removed)
	})
}

// handleProjectTrack submits a project-track flow job for non-Obsidian repos.
func (h *Handler) handleProjectTrack(w http.ResponseWriter, r *http.Request, event PushEvent) {
	if h.jobs == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	// collect commit messages
	var messages []string
	for _, c := range event.Commits {
		messages = append(messages, c.Message)
	}
	if len(messages) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	input, err := json.Marshal(map[string]any{
		"repo":    event.Repository.FullName,
		"commits": messages,
	})
	if err != nil {
		h.logger.Error("marshaling project-track input", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	ctx := context.WithoutCancel(r.Context())
	if err := h.jobs.Submit(ctx, "project-track", input, nil); err != nil {
		h.logger.Error("submitting project-track", "repo", event.Repository.FullName, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("project-track submitted", "repo", event.Repository.FullName, "commits", len(messages))
	w.WriteHeader(http.StatusAccepted)
}

// archiveRemovedFiles archives content for deleted markdown files.
func (h *Handler) archiveRemovedFiles(ctx context.Context, files []string) {
	for _, path := range files {
		slug := slugFromPath(path)
		existing, err := h.contentReader.ContentBySlug(ctx, slug)
		if err != nil {
			// not found — already deleted or never synced, skip
			h.logger.Debug("removed file not found in db, skipping", "path", path, "slug", slug)
			continue
		}
		if err := h.contentWriter.DeleteContent(ctx, existing.ID); err != nil {
			h.logger.Error("archiving removed file", "path", path, "slug", slug, "error", err)
			continue
		}
		h.logger.Info("archived removed file", "path", path, "slug", slug)
	}
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
	existing, err := h.contentReader.ContentBySlug(ctx, slug)
	if err == nil && existing != nil {
		// update existing content — status reflects frontmatter published field
		status := content.StatusDraft
		if parsed.Published {
			status = content.StatusPublished
		}
		_, err := h.contentWriter.UpdateContent(ctx, existing.ID, content.UpdateParams{
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

		// publish if the obsidian file is marked as published and not yet published
		if parsed.Published && existing.Status != content.StatusPublished {
			if _, err := h.contentWriter.PublishContent(ctx, existing.ID); err != nil {
				return fmt.Errorf("publishing content %s: %w", slug, err)
			}
		}

		h.submitContentReview(ctx, existing.ID)
		return nil
	}

	// create new content
	created, err := h.contentWriter.CreateContent(ctx, content.CreateParams{
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
		if _, err := h.contentWriter.PublishContent(ctx, created.ID); err != nil {
			return fmt.Errorf("publishing content %s: %w", slug, err)
		}
	}

	h.submitContentReview(ctx, created.ID)
	return nil
}

// submitContentReview submits a content-review flow job.
// Errors are logged but not propagated — content sync should not fail
// because the AI pipeline is unavailable.
func (h *Handler) submitContentReview(ctx context.Context, contentID uuid.UUID) {
	if h.jobs == nil {
		return
	}
	input, err := json.Marshal(map[string]string{"content_id": contentID.String()})
	if err != nil {
		h.logger.Error("marshaling content-review input", "content_id", contentID, "error", err)
		return
	}
	if err := h.jobs.Submit(ctx, "content-review", input, &contentID); err != nil {
		h.logger.Error("submitting content-review", "content_id", contentID, "error", err)
	}
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
