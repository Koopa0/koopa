package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/note"
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
	CreateContent(ctx context.Context, p *content.CreateParams) (*content.Content, error)
	UpdateContent(ctx context.Context, id uuid.UUID, p *content.UpdateParams) (*content.Content, error)
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
	UpsertNote(ctx context.Context, p *note.UpsertParams) (*note.Note, error)
	ContentHash(ctx context.Context, filePath string) (*string, error)
	ArchiveNote(ctx context.Context, filePath string) error
}

// TagResolver normalizes raw tags and manages note-tag junction records.
type TagResolver interface {
	ResolveTags(ctx context.Context, rawTags []string) []tag.Resolved
	SyncNoteTags(ctx context.Context, noteID int64, tagIDs []uuid.UUID) error
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
	CreateEvent(ctx context.Context, p *activity.RecordParams) (int64, error)
}

// NoteEventRecorder records activity events for knowledge notes and links tags.
type NoteEventRecorder interface {
	EventRecorder
	SyncEventTags(ctx context.Context, eventID int64, tagIDs []uuid.UUID) error
}

// NoteLinkSyncer syncs wikilink edges for a knowledge note.
type NoteLinkSyncer interface {
	SyncNoteLinks(ctx context.Context, noteID int64, links []note.Link) error
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
		h.handleProjectTrack(w, r, &event)
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
