package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/ai/exec"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/event"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/feed/collector"
	"github.com/koopa0/blog-backend/internal/github"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/notion"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/reconcile"
	"github.com/koopa0/blog-backend/internal/tag"
	"github.com/koopa0/blog-backend/internal/webhook"
)

// maxConcurrentOps limits the number of concurrent background operations
// to prevent resource exhaustion from webhook floods.
const maxConcurrentOps = 10

// TopicLookupFunc resolves a topic slug to a UUID.
type TopicLookupFunc func(ctx context.Context, slug string) (uuid.UUID, error)

// ---------------------------------------------------------------------------
// ContentSync — GitHub → content/note sync (A1 + B1 pipeline)
// ---------------------------------------------------------------------------

// ContentSync synchronises Obsidian content and knowledge notes from GitHub.
type ContentSync struct {
	pool       *pgxpool.Pool
	content    *content.Store
	topics     TopicLookupFunc
	fetcher    *github.Client
	jobs       *exec.Runner
	notes      *note.Store
	tags       *tag.Store
	noteEvents *activity.Store
	noteLinks  *note.Store
	logger     *slog.Logger
}

// ContentSyncDeps holds required dependencies for ContentSync.
type ContentSyncDeps struct {
	Pool    *pgxpool.Pool
	Content *content.Store
	Topics  TopicLookupFunc
	Fetcher *github.Client
	Jobs    *exec.Runner
	Logger  *slog.Logger
}

// NewContentSync returns a ContentSync with required dependencies.
// Pool is used for transactional note sync (upsert + tags + links in one tx).
func NewContentSync(deps ContentSyncDeps) *ContentSync {
	return &ContentSync{
		pool:    deps.Pool,
		content: deps.Content,
		topics:  deps.Topics,
		fetcher: deps.Fetcher,
		jobs:    deps.Jobs,
		logger:  deps.Logger,
	}
}

// WithNoteSync sets the note upserter and tag resolver for B1 knowledge note sync.
func (cs *ContentSync) WithNoteSync(n *note.Store, t *tag.Store) {
	cs.notes = n
	cs.tags = t
}

// WithNoteEvents sets the note event recorder for B1 activity tracking.
func (cs *ContentSync) WithNoteEvents(ne *activity.Store) {
	cs.noteEvents = ne
}

// WithNoteLinks sets the note link syncer for wikilink edge extraction.
func (cs *ContentSync) WithNoteLinks(nl *note.Store) {
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
	events        *activity.Store
	comparer      *github.Client
	notionTasks   *notion.Client
	projectRepo   *project.Store
	jobs          *exec.Runner
	bus           *event.Bus
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
func (wr *WebhookRouter) WithActivityRecorder(e *activity.Store, c *github.Client) {
	wr.events = e
	wr.comparer = c
}

// WithNotionTasks sets the Notion client for PR merge → task status updates.
func (wr *WebhookRouter) WithNotionTasks(n *notion.Client) {
	wr.notionTasks = n
}

// WithProjectRepo sets the resolver for GitHub push event project attribution.
func (wr *WebhookRouter) WithProjectRepo(r *project.Store) {
	wr.projectRepo = r
}

// WithJobs sets the job submitter for project-track flow submissions.
func (wr *WebhookRouter) WithJobs(j *exec.Runner) {
	wr.jobs = j
}

// WithEventBus sets the event bus for emitting cross-cutting events.
func (wr *WebhookRouter) WithEventBus(b *event.Bus) {
	wr.bus = b
}

// ---------------------------------------------------------------------------
// Triggers — manual pipeline triggers
// ---------------------------------------------------------------------------

// Triggers handles manually-triggered pipeline operations (collect, reconcile, etc.).
type Triggers struct {
	collector  *collector.Collector
	feeds      *feed.Store
	reconciler *reconcile.Reconciler
	notionSync *notion.Handler
	jobs       *exec.Runner
	logger     *slog.Logger
}

// NewTriggers returns a Triggers with required dependencies.
func NewTriggers(jobs *exec.Runner, logger *slog.Logger) *Triggers {
	return &Triggers{
		jobs:   jobs,
		logger: logger,
	}
}

// WithCollector sets the feed collector and lister for the collect pipeline.
func (tr *Triggers) WithCollector(c *collector.Collector, f *feed.Store) {
	tr.collector = c
	tr.feeds = f
}

// WithReconciler sets the reconciler for manual sync endpoints.
func (tr *Triggers) WithReconciler(r *reconcile.Reconciler) {
	tr.reconciler = r
}

// WithNotionSync sets the Notion syncer for full sync.
func (tr *Triggers) WithNotionSync(n *notion.Handler) {
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

// NewTopicLookup creates a TopicLookupFunc from a function that resolves a topic slug to a UUID.
func NewTopicLookup(fn func(ctx context.Context, slug string) (uuid.UUID, error)) TopicLookupFunc {
	return fn
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
