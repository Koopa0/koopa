package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
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

// ---------------------------------------------------------------------------
// Interface definitions (consumed by sub-structs)
// ---------------------------------------------------------------------------

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
// Defined here (consumer) because importing flowrun would create an import cycle
// (pipeline → flowrun → flow → pipeline). Identical contract: flowrun.Submitter.
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

// NoteEventRecorder records activity events for knowledge notes and links tags.
type NoteEventRecorder interface {
	activity.Recorder
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

// ---------------------------------------------------------------------------
// ContentSync — GitHub → content/note sync (A1 + B1 pipeline)
// ---------------------------------------------------------------------------

// ContentSync synchronises Obsidian content and knowledge notes from GitHub.
type ContentSync struct {
	pool          *pgxpool.Pool
	contentReader ContentReader
	contentWriter ContentWriter
	topics        TopicLookup
	fetcher       GitHubFetcher
	jobs          JobSubmitter
	notes         NoteUpserter
	tags          TagResolver
	noteEvents    NoteEventRecorder
	noteLinks     NoteLinkSyncer
	logger        *slog.Logger
}

// NewContentSync returns a ContentSync with required dependencies.
// pool is used for transactional note sync (upsert + tags + links in one tx).
func NewContentSync(pool *pgxpool.Pool, cr ContentReader, cw ContentWriter, tl TopicLookup, fetcher GitHubFetcher, jobs JobSubmitter, logger *slog.Logger) *ContentSync {
	return &ContentSync{
		pool:          pool,
		contentReader: cr,
		contentWriter: cw,
		topics:        tl,
		fetcher:       fetcher,
		jobs:          jobs,
		logger:        logger,
	}
}

// WithNoteSync sets the note upserter and tag resolver for B1 knowledge note sync.
func (cs *ContentSync) WithNoteSync(n NoteUpserter, t TagResolver) {
	cs.notes = n
	cs.tags = t
}

// WithNoteEvents sets the note event recorder for B1 activity tracking.
func (cs *ContentSync) WithNoteEvents(ne NoteEventRecorder) {
	cs.noteEvents = ne
}

// WithNoteLinks sets the note link syncer for wikilink edge extraction.
func (cs *ContentSync) WithNoteLinks(nl NoteLinkSyncer) {
	cs.noteLinks = nl
}

// ---------------------------------------------------------------------------
// WebhookRouter — HMAC verification, event routing, dedup
// ---------------------------------------------------------------------------

// WebhookRouter verifies GitHub webhooks and routes events to the appropriate handler.
type WebhookRouter struct {
	webhookSecret string
	obsidianRepo  string // "owner/repo" for Obsidian content sync
	botLogin      string // GitHub login to ignore (self-loop protection)
	contentSync   *ContentSync
	dedup         *webhook.DeduplicationCache
	events        activity.Recorder
	comparer      GitHubComparer
	notionTasks   NotionTaskUpdater
	projectRepo   ProjectRepoResolver
	jobs          JobSubmitter
	logger        *slog.Logger
}

// NewWebhookRouter returns a WebhookRouter.
// botLogin is the GitHub username whose pushes should be ignored to prevent self-loops.
// Pass "" to disable self-loop protection.
func NewWebhookRouter(secret, obsidianRepo, botLogin string, cs *ContentSync, logger *slog.Logger) *WebhookRouter {
	return &WebhookRouter{
		webhookSecret: secret,
		obsidianRepo:  obsidianRepo,
		botLogin:      botLogin,
		contentSync:   cs,
		logger:        logger,
	}
}

// WithDedup sets the deduplication cache for webhook replay protection.
func (wr *WebhookRouter) WithDedup(d *webhook.DeduplicationCache) {
	wr.dedup = d
}

// WithActivityRecorder sets the event recorder and GitHub comparer for activity tracking.
func (wr *WebhookRouter) WithActivityRecorder(e activity.Recorder, c GitHubComparer) {
	wr.events = e
	wr.comparer = c
}

// WithNotionTasks sets the Notion client for PR merge → task status updates.
func (wr *WebhookRouter) WithNotionTasks(n NotionTaskUpdater) {
	wr.notionTasks = n
}

// WithProjectRepo sets the resolver for GitHub push event project attribution.
func (wr *WebhookRouter) WithProjectRepo(r ProjectRepoResolver) {
	wr.projectRepo = r
}

// WithJobs sets the job submitter for project-track flow submissions.
func (wr *WebhookRouter) WithJobs(j JobSubmitter) {
	wr.jobs = j
}

// ---------------------------------------------------------------------------
// Triggers — manual pipeline triggers
// ---------------------------------------------------------------------------

// Triggers handles manually-triggered pipeline operations (collect, reconcile, etc.).
type Triggers struct {
	collector  FeedCollector
	feeds      FeedLister
	reconciler Reconciler
	notionSync NotionSyncer
	jobs       JobSubmitter
	logger     *slog.Logger
}

// NewTriggers returns a Triggers with required dependencies.
func NewTriggers(jobs JobSubmitter, logger *slog.Logger) *Triggers {
	return &Triggers{
		jobs:   jobs,
		logger: logger,
	}
}

// WithCollector sets the feed collector and lister for the collect pipeline.
func (tr *Triggers) WithCollector(c FeedCollector, f FeedLister) {
	tr.collector = c
	tr.feeds = f
}

// WithReconciler sets the reconciler for manual sync endpoints.
func (tr *Triggers) WithReconciler(r Reconciler) {
	tr.reconciler = r
}

// WithNotionSync sets the Notion syncer for full sync.
func (tr *Triggers) WithNotionSync(n NotionSyncer) {
	tr.notionSync = n
}

// ---------------------------------------------------------------------------
// Handler — thin facade for route registration + background goroutine pool
// ---------------------------------------------------------------------------

// Handler is a thin facade that delegates HTTP requests to the appropriate
// sub-struct (ContentSync, WebhookRouter, Triggers) and manages a shared
// background goroutine pool with backpressure.
type Handler struct {
	content  *ContentSync
	webhook  *WebhookRouter
	triggers *Triggers
	wg       sync.WaitGroup
	sem      chan struct{}
	logger   *slog.Logger
}

// NewHandler returns a pipeline Handler that delegates to the given sub-structs.
func NewHandler(cs *ContentSync, wr *WebhookRouter, tr *Triggers, logger *slog.Logger) *Handler {
	return &Handler{
		content:  cs,
		webhook:  wr,
		triggers: tr,
		sem:      make(chan struct{}, maxConcurrentOps),
		logger:   logger,
	}
}

// NewTopicLookup creates a TopicLookup from a function that returns a topic with an ID.
func NewTopicLookup(fn func(ctx context.Context, slug string) (uuid.UUID, error)) TopicLookup {
	return &topicLookupFunc{fn: fn}
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

// ---------------------------------------------------------------------------
// Facade HTTP methods — delegate to sub-structs
// ---------------------------------------------------------------------------

// Sync handles POST /api/pipeline/sync — full Obsidian sync from GitHub.
func (h *Handler) Sync(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`)
	h.goBackground("sync", func() {
		ctx := context.WithoutCancel(r.Context())
		h.content.SyncAllFromGitHub(ctx)
	})
}

// SyncAllFromGitHub delegates to ContentSync for direct (non-HTTP) callers
// such as cron jobs and startup sync.
func (h *Handler) SyncAllFromGitHub(ctx context.Context) {
	h.content.SyncAllFromGitHub(ctx)
}

// WebhookGithub handles POST /api/webhook/github.
func (h *Handler) WebhookGithub(w http.ResponseWriter, r *http.Request) {
	h.webhook.Handle(w, r, h.goBackground)
}

// Collect handles POST /api/pipeline/collect.
func (h *Handler) Collect(w http.ResponseWriter, r *http.Request) {
	h.triggers.Collect(w, r, h.goBackground)
}

// NotionSync handles POST /api/pipeline/notion-sync — full Notion sync.
func (h *Handler) NotionSync(w http.ResponseWriter, r *http.Request) {
	h.triggers.NotionSync(w, r, h.goBackground)
}

// Reconcile handles POST /api/pipeline/reconcile — full reconciliation.
func (h *Handler) Reconcile(w http.ResponseWriter, r *http.Request) {
	h.triggers.Reconcile(w, r, h.goBackground)
}

// Generate handles POST /api/pipeline/generate.
func (h *Handler) Generate(w http.ResponseWriter, r *http.Request) {
	h.triggers.Generate(w, r)
}

// Digest handles POST /api/pipeline/digest.
func (h *Handler) Digest(w http.ResponseWriter, r *http.Request) {
	h.triggers.Digest(w, r)
}

// Bookmark handles POST /api/pipeline/bookmark.
func (h *Handler) Bookmark(w http.ResponseWriter, r *http.Request) {
	h.triggers.Bookmark(w, r)
}
