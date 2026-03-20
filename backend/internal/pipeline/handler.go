package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/api"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/obsidian"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/tag"
	"github.com/koopa0/blog-backend/internal/webhook"
)

// maxConcurrentOps limits the number of concurrent background operations
// to prevent resource exhaustion from webhook floods.
const maxConcurrentOps = 10

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

// NoteUpserter upserts and archives obsidian knowledge notes.
type NoteUpserter interface {
	UpsertNote(ctx context.Context, p note.UpsertParams) (*note.Note, error)
	ContentHash(ctx context.Context, filePath string) (*string, error)
	ArchiveNote(ctx context.Context, filePath string) error
	WithTx(tx pgx.Tx) *note.Store
}

// TagResolver normalizes raw tags and manages note-tag junction records.
type TagResolver interface {
	ResolveTags(ctx context.Context, rawTags []string) []tag.Resolved
	SyncNoteTags(ctx context.Context, noteID int64, tagIDs []uuid.UUID) error
	WithTx(tx pgx.Tx) *tag.Store
}

// GitHubComparer fetches diff stats between two commits.
type GitHubComparer interface {
	Compare(ctx context.Context, repo, base, head string) (*activity.DiffStats, error)
}

// ProjectRepoResolver resolves a GitHub repo full name to a project.
type ProjectRepoResolver interface {
	ProjectByRepo(ctx context.Context, repo string) (*project.Project, error)
}

// EventRecorder records activity events for tracking.
type EventRecorder interface {
	CreateEvent(ctx context.Context, p activity.RecordParams) (int64, error)
}

// NoteEventRecorder records activity events for knowledge notes and links tags.
type NoteEventRecorder interface {
	EventRecorder
	SyncEventTags(ctx context.Context, eventID int64, tagIDs []uuid.UUID) error
}

// NoteLinkSyncer syncs wikilink edges for a knowledge note.
type NoteLinkSyncer interface {
	SyncNoteLinks(ctx context.Context, noteID int64, links []note.NoteLink) error
	WithTx(tx pgx.Tx) *note.Store
}

// NotionTaskUpdater updates a Notion page status.
type NotionTaskUpdater interface {
	UpdatePageStatus(ctx context.Context, pageID, status string) error
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
	sem           chan struct{}
	pool          *pgxpool.Pool
	contentReader ContentReader
	contentWriter ContentWriter
	topics        TopicLookup
	fetcher       GitHubFetcher
	jobs          JobSubmitter
	collector     FeedCollector
	feeds         FeedLister
	reconciler    Reconciler
	notionSync    NotionSyncer
	notes         NoteUpserter
	tags          TagResolver
	comparer      GitHubComparer
	events        EventRecorder
	noteEvents    NoteEventRecorder
	noteLinks     NoteLinkSyncer
	notionTasks   NotionTaskUpdater
	projectRepo   ProjectRepoResolver
	dedup         *webhook.DeduplicationCache
	webhookSecret string
	obsidianRepo  string // "owner/repo" for Obsidian content sync
	botLogin      string // GitHub login to ignore (self-loop protection)
	logger        *slog.Logger
}

// NewHandler returns a pipeline Handler.
// pool is used for transactional note sync (upsert + tags + links in one tx).
// botLogin is the GitHub username whose pushes should be ignored to prevent self-loops.
// Pass "" to disable self-loop protection.
func NewHandler(pool *pgxpool.Pool, cr ContentReader, cw ContentWriter, tl TopicLookup, fetcher GitHubFetcher, jobs JobSubmitter, webhookSecret, obsidianRepo, botLogin string, logger *slog.Logger) *Handler {
	return &Handler{
		sem:           make(chan struct{}, maxConcurrentOps),
		pool:          pool,
		contentReader: cr,
		contentWriter: cw,
		topics:        tl,
		fetcher:       fetcher,
		jobs:          jobs,
		webhookSecret: webhookSecret,
		obsidianRepo:  obsidianRepo,
		botLogin:      botLogin,
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

// SetNoteSync sets the note upserter and tag resolver for B1 knowledge note sync.
func (h *Handler) SetNoteSync(n NoteUpserter, t TagResolver) {
	h.notes = n
	h.tags = t
}

// SetActivityRecorder sets the event recorder and GitHub comparer for activity tracking.
func (h *Handler) SetActivityRecorder(e EventRecorder, c GitHubComparer) {
	h.events = e
	h.comparer = c
}

// SetNoteLinkSync sets the note link syncer for wikilink edge extraction.
func (h *Handler) SetNoteLinkSync(n NoteLinkSyncer) {
	h.noteLinks = n
}

// SetNoteEventRecorder sets the note event recorder for B1 activity tracking.
func (h *Handler) SetNoteEventRecorder(ne NoteEventRecorder) {
	h.noteEvents = ne
}

// SetNotionTaskUpdater sets the Notion client for PR merge → task status updates.
func (h *Handler) SetNotionTaskUpdater(n NotionTaskUpdater) {
	h.notionTasks = n
}

// SetProjectRepoResolver sets the resolver for GitHub push event project attribution.
func (h *Handler) SetProjectRepoResolver(r ProjectRepoResolver) {
	h.projectRepo = r
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

// goBackground runs fn in a tracked goroutine with backpressure.
// If all semaphore slots are busy, the operation is dropped and logged.
func (h *Handler) goBackground(name string, fn func()) {
	select {
	case h.sem <- struct{}{}:
		h.wg.Go(func() {
			defer func() { <-h.sem }()
			fn()
		})
	default:
		h.logger.Warn("pipeline: dropping background operation (at capacity)", "operation", name)
	}
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
	h.goBackground("sync", func() {
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
			if errors.Is(err, ErrGitHubNotFound) {
				h.logger.Warn("sync: file not found (deleted?)", "path", path)
			} else {
				h.logger.Error("sync: syncing file", "path", path, "error", err)
			}
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
		api.Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "notion sync not configured")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`)
	h.goBackground("notion-sync", func() {
		ctx := context.WithoutCancel(r.Context())
		h.notionSync.SyncAll(ctx)
	})
}

// Reconcile handles POST /api/pipeline/reconcile — full Obsidian + Notion reconciliation.
func (h *Handler) Reconcile(w http.ResponseWriter, r *http.Request) {
	if h.reconciler == nil {
		api.Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "reconciler not configured")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`)
	h.goBackground("reconcile", func() {
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
		api.Error(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "collector not configured")
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
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list feeds")
		return
	}

	// respond 202 immediately, collect in background
	w.WriteHeader(http.StatusAccepted)

	h.goBackground("collect", func() {
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
	api.Error(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "not implemented")
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
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.StartDate == "" || req.EndDate == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "start_date and end_date are required")
		return
	}

	input, err := json.Marshal(req)
	if err != nil {
		h.logger.Error("marshaling digest input", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	if err := h.jobs.Submit(r.Context(), "digest-generate", input, nil); err != nil {
		h.logger.Error("submitting digest-generate", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to submit digest job")
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
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if _, err := uuid.Parse(req.CollectedDataID); err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid collected_data_id")
		return
	}

	input, err := json.Marshal(req)
	if err != nil {
		h.logger.Error("marshaling bookmark input", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	if err := h.jobs.Submit(r.Context(), "bookmark-generate", input, nil); err != nil {
		h.logger.Error("submitting bookmark-generate", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to submit bookmark job")
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

	// route by event type
	eventType := r.Header.Get("X-GitHub-Event")
	switch eventType {
	case "pull_request":
		h.handlePullRequest(w, r, body)
		return
	case "push":
		// handled below
	default:
		w.WriteHeader(http.StatusOK)
		return
	}

	var event PushEvent
	if err := json.Unmarshal(body, &event); err != nil {
		h.logger.Error("parsing push event", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// B2 self-loop protection: ignore pushes from the bot account.
	// This check runs AFTER HMAC verification so that an attacker cannot
	// craft a payload with Sender.Login == botLogin to bypass processing.
	if h.botLogin != "" && event.Sender.Login == h.botLogin {
		h.logger.Info("ignoring push from bot", "sender", event.Sender.Login)
		w.WriteHeader(http.StatusOK)
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

	// split changed files into public content (A1) and knowledge notes (B1)
	changed := event.ChangedFiles()
	removedAll := event.RemovedFiles()

	publicFiles := filterPublicMarkdown(changed)
	publicRemoved := filterPublicMarkdown(removedAll)
	knowledgeFiles := filterKnowledgeMarkdown(changed)
	knowledgeRemoved := filterKnowledgeMarkdown(removedAll)

	if len(publicFiles) == 0 && len(publicRemoved) == 0 &&
		len(knowledgeFiles) == 0 && len(knowledgeRemoved) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	// respond 202 immediately, process in background
	w.WriteHeader(http.StatusAccepted)

	h.goBackground("webhook-push", func() {
		ctx := context.WithoutCancel(r.Context())

		// A1: public content sync
		h.syncFiles(ctx, publicFiles)
		h.archiveRemovedFiles(ctx, publicRemoved)

		// B1: knowledge note sync
		if h.notes != nil && h.tags != nil {
			h.syncKnowledgeNotes(ctx, knowledgeFiles)
			h.archiveKnowledgeNotes(ctx, knowledgeRemoved)
		}
	})
}

// zeroSHA is the all-zeros SHA that GitHub sends for new branch creation.
const zeroSHA = "0000000000000000000000000000000000000000"

// handleProjectTrack submits a project-track flow job and records an activity
// event for non-Obsidian repos.
func (h *Handler) handleProjectTrack(w http.ResponseWriter, r *http.Request, event PushEvent) {
	// collect commit messages
	var messages []string
	for _, c := range event.Commits {
		messages = append(messages, c.Message)
	}
	if len(messages) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	// respond 202 immediately, do all work in background
	w.WriteHeader(http.StatusAccepted)

	ctx := context.WithoutCancel(r.Context())
	h.goBackground("project-track", func() {
		// submit project-track flow job (best-effort)
		if h.jobs != nil {
			input, err := json.Marshal(map[string]any{
				"repo":    event.Repository.FullName,
				"commits": messages,
			})
			if err != nil {
				h.logger.Error("marshaling project-track input", "error", err)
			} else if err := h.jobs.Submit(ctx, "project-track", input, nil); err != nil {
				h.logger.Error("submitting project-track", "repo", event.Repository.FullName, "error", err)
			} else {
				h.logger.Info("project-track submitted", "repo", event.Repository.FullName, "commits", len(messages))
			}
		}

		// record activity event
		if h.events != nil {
			h.recordPushEvent(ctx, event)
		}
	})
}

// recordPushEvent records a push activity event, optionally enriched with diff stats.
func (h *Handler) recordPushEvent(ctx context.Context, event PushEvent) {
	repo := event.Repository.FullName
	ref := event.Ref

	// build title from first commit message (first line only, capped at 500 chars)
	var titlePtr *string
	if len(event.Commits) > 0 {
		title := event.Commits[0].Message
		if idx := strings.IndexByte(title, '\n'); idx > 0 {
			title = title[:idx]
		}
		if len(title) > 500 {
			title = title[:500]
		}
		titlePtr = &title
	}

	// fetch diff stats from Compare API (best-effort)
	var metadata json.RawMessage
	if h.comparer != nil && event.Before != zeroSHA && isSHA(event.Before) && isSHA(event.After) {
		stats, err := h.comparer.Compare(ctx, repo, event.Before, event.After)
		if err != nil {
			h.logger.Warn("fetching diff stats", "repo", repo, "error", err)
		} else {
			stats.CommitCount = len(event.Commits)
			if data, err := json.Marshal(stats); err == nil {
				metadata = data
			}
		}
	}

	// Resolve project: try projects.repo match, fallback to raw repo name.
	// Normalize-on-write so all downstream consumers see clean slugs.
	projectName := repo
	if h.projectRepo != nil {
		if proj, projErr := h.projectRepo.ProjectByRepo(ctx, repo); projErr == nil {
			projectName = proj.Slug
		}
	}

	// source_id: use after SHA for dedup
	sourceID := event.After
	p := activity.RecordParams{
		SourceID:  &sourceID,
		Timestamp: time.Now(),
		EventType: "push",
		Source:    "github",
		Project:   &projectName,
		Repo:      &repo,
		Ref:       &ref,
		Title:     titlePtr,
		Metadata:  metadata,
	}

	if _, err := h.events.CreateEvent(ctx, p); err != nil {
		h.logger.Error("recording push activity event", "repo", repo, "error", err)
	}
}

// recordNoteEvent records an activity event for a knowledge note sync (best-effort).
func (h *Handler) recordNoteEvent(ctx context.Context, filePath, bodyHash string, parsed *obsidian.Knowledge, tagIDs []uuid.UUID, isNew bool) {
	eventType := "note_updated"
	if isNew {
		eventType = "note_created"
	}

	// source_id: bodyHash for dedup — each content change creates one event,
	// re-syncs of unchanged content are deduplicated.
	sourceID := bodyHash

	// metadata via json.Marshal to avoid JSON injection from file paths
	meta, err := json.Marshal(map[string]string{
		"note_type": parsed.Type,
		"file_path": filePath,
	})
	if err != nil {
		h.logger.Error("marshaling note event metadata", "path", filePath, "error", err)
		return
	}

	var titlePtr *string
	if parsed.Title != "" {
		titlePtr = &parsed.Title
	}

	var contextPtr *string
	if parsed.Context != "" {
		contextPtr = &parsed.Context
	}

	p := activity.RecordParams{
		SourceID:  &sourceID,
		Timestamp: time.Now(),
		EventType: eventType,
		Source:    "obsidian",
		Project:   contextPtr,
		Title:     titlePtr,
		Metadata:  meta,
	}

	eventID, err := h.noteEvents.CreateEvent(ctx, p)
	if err != nil {
		h.logger.Error("recording note activity event", "path", filePath, "error", err)
		return
	}

	if len(tagIDs) > 0 {
		if err := h.noteEvents.SyncEventTags(ctx, eventID, tagIDs); err != nil {
			h.logger.Error("syncing note event tags", "path", filePath, "error", err)
		}
	}
}

// notionURLPattern extracts 32-character hex Notion page IDs from URLs.
var notionURLPattern = regexp.MustCompile(`https?://(?:www\.)?notion\.so/\S*?([0-9a-f]{32})\b`)

// handlePullRequest routes pull_request webhook events.
func (h *Handler) handlePullRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	var event PullRequestEvent
	if err := json.Unmarshal(body, &event); err != nil {
		h.logger.Error("parsing pull_request event", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// only process merged PRs (action=closed + merged=true)
	if event.Action != "closed" || !event.PullRequest.Merged {
		w.WriteHeader(http.StatusOK)
		return
	}

	if h.notionTasks == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	// respond 202 immediately, process in background
	w.WriteHeader(http.StatusAccepted)

	h.goBackground("pr-merge", func() {
		ctx := context.WithoutCancel(r.Context())
		h.handlePRMerge(ctx, event)
	})
}

// maxNotionUpdatesPerPR caps the number of Notion pages updated per PR merge
// to bound goroutine lifetime and rate-limiter pressure.
const maxNotionUpdatesPerPR = 10

// handlePRMerge extracts Notion page IDs from the PR body and marks them as Done.
func (h *Handler) handlePRMerge(ctx context.Context, event PullRequestEvent) {
	matches := notionURLPattern.FindAllStringSubmatch(event.PullRequest.Body, -1)
	if len(matches) == 0 {
		return
	}

	// deduplicate page IDs (a PR body might reference the same page multiple times)
	seen := make(map[string]bool, len(matches))
	for _, m := range matches {
		pageID := m[1]
		if seen[pageID] {
			continue
		}
		if len(seen) >= maxNotionUpdatesPerPR {
			h.logger.Warn("PR body exceeds max Notion page ID limit, skipping remaining",
				"limit", maxNotionUpdatesPerPR,
				"pr", event.PullRequest.Number,
			)
			break
		}
		seen[pageID] = true

		// format as UUID: 8-4-4-4-12
		formattedID := fmt.Sprintf("%s-%s-%s-%s-%s",
			pageID[:8], pageID[8:12], pageID[12:16], pageID[16:20], pageID[20:])

		if err := h.notionTasks.UpdatePageStatus(ctx, formattedID, "Done"); err != nil {
			h.logger.Error("updating notion task status",
				"page_id", formattedID,
				"repo", event.Repository.FullName,
				"pr", event.PullRequest.Number,
				"error", err,
			)
			continue
		}
		h.logger.Info("notion task marked done",
			"page_id", formattedID,
			"repo", event.Repository.FullName,
			"pr", event.PullRequest.Number,
		)
	}
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

// excludedKnowledgePrefixes lists directories that should NOT be synced as knowledge notes.
var excludedKnowledgePrefixes = []string{
	"10-Public-Content/", // handled by A1 pipeline
	"99-System/",         // templates and system files
	".claude/",           // Claude Code skills/commands
	".obsidian/",         // Obsidian config
}

// filterKnowledgeMarkdown returns .md files that are NOT in excluded directories
// and NOT root-level files (README.md, CLAUDE.md, etc.).
func filterKnowledgeMarkdown(files []string) []string {
	var result []string
	for _, f := range files {
		if !strings.HasSuffix(f, ".md") {
			continue
		}
		// Sanitize path to prevent traversal (e.g. "foo/../99-System/bar.md").
		clean := path.Clean(f)
		// exclude root-level .md files (no directory prefix)
		if !strings.Contains(clean, "/") {
			continue
		}
		excluded := false
		for _, prefix := range excludedKnowledgePrefixes {
			if strings.HasPrefix(clean, prefix) {
				excluded = true
				break
			}
		}
		if !excluded {
			result = append(result, clean)
		}
	}
	return result
}

// syncKnowledgeNotes fetches and upserts each knowledge note.
func (h *Handler) syncKnowledgeNotes(ctx context.Context, files []string) {
	for _, path := range files {
		if err := h.syncKnowledgeNote(ctx, path); err != nil {
			h.logger.Error("syncing knowledge note", "path", path, "error", err)
			continue
		}
		h.logger.Info("synced knowledge note", "path", path)
	}
}

// syncKnowledgeNote fetches a single file from GitHub and upserts it as a knowledge note.
func (h *Handler) syncKnowledgeNote(ctx context.Context, path string) error {
	raw, err := h.fetcher.FileContent(ctx, path)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", path, err)
	}

	parsed, body, err := obsidian.ParseKnowledge(raw)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	// type is hard required — skip if missing
	if parsed.Type == "" {
		h.logger.Warn("knowledge note missing type, skipping", "path", path)
		return nil
	}

	// compute content hash (SHA-256 of body only)
	bodyHash := sha256Hex(body)

	// check if body changed — skip SplitCamelCase if hash matches
	var searchText string
	existingHash, err := h.notes.ContentHash(ctx, path)
	isNewNote := errors.Is(err, note.ErrNotFound)
	hashChanged := err != nil || existingHash == nil || *existingHash != bodyHash

	if hashChanged {
		searchText = obsidian.SplitCamelCase(body)
	}

	// build upsert params
	p := note.UpsertParams{
		FilePath:    path,
		ContentHash: &bodyHash,
	}

	// set optional fields from parsed frontmatter
	if parsed.Title != "" {
		p.Title = &parsed.Title
	}
	p.Type = &parsed.Type
	if parsed.Source != "" {
		p.Source = &parsed.Source
	}
	if parsed.Context != "" {
		p.Context = &parsed.Context
	}
	if parsed.Status != "" {
		p.Status = &parsed.Status
	}
	p.Tags = parsed.Tags
	if parsed.Difficulty != "" {
		p.Difficulty = &parsed.Difficulty
	}
	if parsed.LeetcodeID != 0 && parsed.LeetcodeID <= math.MaxInt32 {
		id := int32(parsed.LeetcodeID) // #nosec G115 -- bounds checked above
		p.LeetcodeID = &id
	}
	if parsed.Book != "" {
		p.Book = &parsed.Book
	}
	if parsed.Chapter != "" {
		p.Chapter = &parsed.Chapter
	}
	if parsed.NotionTaskID != "" {
		p.NotionTaskID = &parsed.NotionTaskID
	}

	if hashChanged {
		p.ContentText = &body
		p.SearchText = &searchText
	}

	// === BEGIN TRANSACTION: upsert note + tag sync + link sync ===
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning note sync tx for %s: %w", path, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on committed tx is no-op

	txNotes := h.notes.WithTx(tx)
	txTags := h.tags.WithTx(tx)

	upserted, err := txNotes.UpsertNote(ctx, p)
	if err != nil {
		return fmt.Errorf("upserting note %s: %w", path, err)
	}

	// tag normalization (resolution runs outside tx for best-effort alias creation)
	resolved := h.tags.ResolveTags(ctx, parsed.Tags)
	var tagIDs []uuid.UUID
	for _, r := range resolved {
		if r.TagID != nil {
			tagIDs = append(tagIDs, *r.TagID)
		}
	}
	// junction sync within tx
	if err := txTags.SyncNoteTags(ctx, upserted.ID, tagIDs); err != nil {
		return fmt.Errorf("syncing tags for %s: %w", path, err)
	}

	// wikilink edge sync within tx (only when content changed — includes clearing old links)
	if h.noteLinks != nil && hashChanged && p.ContentText != nil {
		txLinks := h.noteLinks.WithTx(tx)
		links := obsidian.ParseWikilinks(*p.ContentText)
		noteLinks := make([]note.NoteLink, len(links))
		for i, l := range links {
			noteLinks[i] = note.NoteLink{TargetPath: l.Path}
			if l.Display != "" {
				noteLinks[i].LinkText = &l.Display
			}
		}
		if linkErr := txLinks.SyncNoteLinks(ctx, upserted.ID, noteLinks); linkErr != nil {
			return fmt.Errorf("syncing note links for %s: %w", path, linkErr)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing note sync tx for %s: %w", path, err)
	}
	// === END TRANSACTION ===

	// Record activity event (best-effort, outside tx). Dedup handled by ON CONFLICT on sourceID=bodyHash.
	if h.noteEvents != nil {
		h.recordNoteEvent(ctx, path, bodyHash, parsed, tagIDs, isNewNote)
	}

	return nil
}

// archiveKnowledgeNotes archives removed knowledge notes.
func (h *Handler) archiveKnowledgeNotes(ctx context.Context, files []string) {
	for _, path := range files {
		if err := h.notes.ArchiveNote(ctx, path); err != nil {
			h.logger.Error("archiving knowledge note", "path", path, "error", err)
			continue
		}
		h.logger.Info("archived knowledge note", "path", path)
	}
}

// isSHA returns true if s looks like a 40-character hex SHA.
func isSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// sha256Hex returns the hex-encoded SHA-256 hash of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
