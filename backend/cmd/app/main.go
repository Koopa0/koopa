package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/anthropic"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pgvector/pgvector-go"
	"github.com/robfig/cron/v3"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/auth"
	"github.com/koopa0/blog-backend/internal/budget"
	"github.com/koopa0/blog-backend/internal/feed/entry"
	"github.com/koopa0/blog-backend/internal/collector"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/event"
	"github.com/koopa0/blog-backend/internal/feed"
	aiflow "github.com/koopa0/blog-backend/internal/ai"
	"github.com/koopa0/blog-backend/internal/ai/exec"
	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/learning"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/notify"
	"github.com/koopa0/blog-backend/internal/notion"
	"github.com/koopa0/blog-backend/internal/pipeline"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/reconcile"
	"github.com/koopa0/blog-backend/internal/review"
	"github.com/koopa0/blog-backend/internal/server"
	"github.com/koopa0/blog-backend/internal/session"
	"github.com/koopa0/blog-backend/internal/stats"
	"github.com/koopa0/blog-backend/internal/tag"
	"github.com/koopa0/blog-backend/internal/task"
	"github.com/koopa0/blog-backend/internal/topic"
	"github.com/koopa0/blog-backend/internal/monitor"
	"github.com/koopa0/blog-backend/internal/upload"
	"github.com/koopa0/blog-backend/internal/webhook"
)

type config struct {
	Port                string
	DatabaseURL         string
	JWTSecret           string
	CORSOrigin          string
	SiteURL             string
	GitHubWebhookSecret string
	GitHubToken         string
	GitHubRepo          string
	GitHubBotLogin      string
	R2Endpoint          string
	R2AccessKeyID       string
	R2SecretAccessKey   string
	R2Bucket            string
	R2PublicURL         string
	GeminiModel         string
	ClaudeModel         string
	NotionAPIKey        string
	NotionWebhookSecret string
	LINEChannelToken    string
	LINEUserID          string
	TelegramBotToken    string
	TelegramChatID      string
	GoogleClientID      string
	GoogleClientSecret  string
	GoogleRedirectURI   string
	AdminEmail          string
	MockMode            bool
}

// shutdownHardDeadline is the maximum time allowed for the entire graceful
// shutdown sequence (HTTP drain + defer cleanup chain). If shutdown takes
// longer, the process is forcibly terminated. This prevents a single hung
// component (e.g. a Notion API call that ignores context cancellation)
// from keeping the process alive indefinitely.
// Budget: 10s HTTP drain + 3min flow timeout + 5min sync timeout + margin.
const shutdownHardDeadline = 5 * time.Minute

func main() {
	logger := slog.New(server.NewSanitizingHandler(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(logger); err != nil {
		logger.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg := loadConfig(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Hard deadline: if graceful shutdown (HTTP drain + defer cleanup) takes
	// longer than shutdownHardDeadline, force-exit the process. This prevents
	// a single hung component from keeping the process alive indefinitely.
	context.AfterFunc(ctx, func() {
		time.AfterFunc(shutdownHardDeadline, func() {
			logger.Error("graceful shutdown timed out, forcing exit",
				"deadline", shutdownHardDeadline)
			os.Exit(1) //nolint:revive // intentional force-exit on shutdown timeout
		})
	})

	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("parsing database config: %w", err)
	}
	poolCfg.MaxConns = 10
	poolCfg.MinConns = 2
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer pool.Close()

	if pingErr := pool.Ping(ctx); pingErr != nil {
		return fmt.Errorf("pinging database: %w", pingErr)
	}
	logger.Info("database connected")

	if migrateErr := runMigrations(cfg.DatabaseURL, logger); migrateErr != nil {
		return fmt.Errorf("running migrations: %w", migrateErr)
	}

	// stores
	authStore := auth.NewStore(pool)
	topicStore := topic.NewStore(pool)
	contentStore := content.NewStore(pool)
	projectStore := project.NewStore(pool)
	reviewStore := review.NewStore(pool)
	collectedStore := entry.NewStore(pool)
	monitorStore := monitor.NewStore(pool)
	flowrunStore := exec.NewStore(pool)
	feedStore := feed.NewStore(pool, logger)
	goalStore := goal.NewStore(pool)
	tagStore := tag.NewStore(pool)
	sessionStore := session.NewStore(pool)
	notionSourceStore := notion.NewStore(pool)
	taskStore := task.NewStore(pool)

	activityStore := activity.NewStore(pool)

	// timezone: all flows and cron jobs run in Asia/Taipei
	taipeiLoc, err := time.LoadLocation("Asia/Taipei")
	if err != nil {
		return fmt.Errorf("loading Asia/Taipei timezone: %w", err)
	}

	// collector + budget
	feedCollector := collector.New(collectedStore, feedStore, monitorStore, logger)
	defer feedCollector.Stop()
	tokenBudget := budget.New(500_000)

	// caches (Ristretto v2 — TinyLFU admission, per-item TTL)
	c, err := createCaches()
	if err != nil {
		return err
	}
	defer c.graph.Close()
	defer c.feed.Close()
	defer c.topic.Close()
	defer c.source.Close()

	// upload
	s3Client := upload.NewS3Client(ctx, cfg.R2Endpoint, cfg.R2AccessKeyID, cfg.R2SecretAccessKey)

	// notification providers
	notifier := setupNotifiers(&cfg, logger)

	// wire notifier to feed store for auto-disable alerts
	feedStore.SetAlerts(notifier)

	// notion client (used by morning brief flow and webhook handler)
	notionClient := notion.NewClient(cfg.NotionAPIKey)

	// github client (used by weekly review flow and pipeline handler)
	githubFetcher := pipeline.NewGitHub(cfg.GitHubToken, cfg.GitHubRepo)

	// AI pipeline — Genkit + flow registry + runner
	aiRes, err := setupAI(ctx, &cfg, &aiDeps{
		flowrunStore:   flowrunStore,
		contentStore:   contentStore,
		reviewStore:    reviewStore,
		topicStore:     topicStore,
		collectedStore: collectedStore,
		projectStore:   projectStore,
		taskStore:      taskStore,
		activityStore:  activityStore,
		githubFetcher:  githubFetcher,
		notifier:       notifier,
		tokenBudget:    tokenBudget,
		taipeiLoc:      taipeiLoc,
		logger:         logger,
	})
	if err != nil {
		return err
	}
	runner := aiRes.runner

	bizMetrics := server.NewMetrics()
	runner.SetObserver(exec.NewMetricsObserver(bizMetrics.FlowDuration))
	runner.Start(ctx)
	defer runner.Stop()

	// reconciler: weekly Obsidian + Notion comparison
	reconcileStore := reconcile.NewStore(pool)
	recon := reconcile.New(
		githubFetcher, contentStore,
		projectStore, goalStore,
		notionClient, notifier,
		notionSourceStore,
		logger,
	)
	recon.WithRunSaver(reconcileStore)

	// webhook replay protection: shared dedup cache with 10-minute TTL
	webhookDedup := webhook.NewDeduplicationCache(10 * time.Minute)
	defer webhookDedup.Stop()

	// event bus: cross-cutting event dispatch for observability
	bus := event.New()
	bus.On(event.WebhookGitHubPush, func(_ context.Context, payload any) error {
		if m, ok := payload.(map[string]any); ok {
			logger.Info("event: github push", "repo", m["repo"], "ref", m["ref"], "source", m["source"])
		}
		return nil
	})
	bus.On(event.NotionPageUpdated, func(_ context.Context, payload any) error {
		if m, ok := payload.(map[string]any); ok {
			logger.Info("event: notion page updated", "page_id", m["page_id"], "role", m["role"])
		}
		return nil
	})

	// notion webhook handler
	notionHandler := notion.NewHandler(
		notionClient, notionSourceStore, c.source,
		projectStore, goalStore, taskStore, runner,
		cfg.NotionWebhookSecret, logger,
		notion.WithDedup(webhookDedup),
		notion.WithEventRecorder(activityStore),
		notion.WithProjectStore(projectStore),
		notion.WithGoalIDResolver(goalStore),
		notion.WithEventBus(bus),
	)
	defer notionHandler.Wait() // drain background SyncRole goroutines

	// pipeline dependencies
	topicLookup := pipeline.NewTopicLookup(func(ctx context.Context, slug string) (uuid.UUID, error) {
		t, err := topicStore.TopicBySlug(ctx, slug)
		if err != nil {
			return uuid.UUID{}, err
		}
		return t.ID, nil
	})

	noteStore := note.NewStore(pool)

	// pipeline: content sync (A1 + B1)
	contentSync := pipeline.NewContentSync(pool, contentStore, contentStore, topicLookup, githubFetcher, runner, logger)
	contentSync.WithNoteSync(noteStore, tagStore)
	contentSync.WithNoteEvents(activityStore)
	contentSync.WithNoteLinks(noteStore)

	// pipeline: webhook router
	webhookRouter := pipeline.NewWebhookRouter(cfg.GitHubWebhookSecret, cfg.GitHubRepo, cfg.GitHubBotLogin, contentSync, logger)
	webhookRouter.WithDedup(webhookDedup)
	webhookRouter.WithActivityRecorder(activityStore, githubFetcher)
	webhookRouter.WithNotionTasks(notionClient)
	webhookRouter.WithProjectRepo(projectStore)
	webhookRouter.WithJobs(runner)
	webhookRouter.WithEventBus(bus)

	// pipeline: manual triggers
	triggers := pipeline.NewTriggers(runner, logger)
	triggers.WithCollector(feedCollector, feedStore)
	triggers.WithReconciler(recon)
	triggers.WithNotionSync(notionHandler)

	// pipeline: facade handler
	pipelineHandler := pipeline.NewHandler(contentSync, webhookRouter, triggers, logger)
	defer pipelineHandler.Wait() // drain in-flight background operations before exit

	// cron: register all scheduled jobs
	cronScheduler := cron.New(cron.WithLocation(taipeiLoc))
	defer cronScheduler.Stop()
	registerCronJobs(cronScheduler, &cronDeps{
		flowrunStore:   flowrunStore,
		feedStore:      feedStore,
		authStore:      authStore,
		collectedStore: collectedStore,
		sessionStore:   sessionStore,
		activityStore:  activityStore,
		projectStore:   projectStore,
		noteStore:      noteStore,
		runner:         runner,
		feedCollector:  feedCollector,
		notifier:       notifier,
		tokenBudget:    tokenBudget,
		recon:          recon,
		contentSync:    contentSync,
		notionHandler:  notionHandler,
		noteEmbedder:   aiRes.noteEmbedder,
		genkitInstance: aiRes.genkit,
		logger:         logger,
	}, ctx)
	cronScheduler.Start()

	deps := server.Deps{
		Pool: pool,
		Auth: auth.NewHandler(authStore, cfg.JWTSecret, &auth.GoogleConfig{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURI:  cfg.GoogleRedirectURI,
			AdminEmail:   cfg.AdminEmail,
			FrontendURL:  cfg.CORSOrigin,
		}, logger),
		Topic:     topic.NewHandler(topicStore, contentStore, c.topic, logger),
		Content:   content.NewHandler(contentStore, cfg.SiteURL, c.graph, c.feed, logger),
		Project:   project.NewHandler(projectStore, logger),
		Review:    review.NewHandler(reviewStore, logger),
		Collected: entry.NewHandler(collectedStore, logger),
		Tracking:  monitor.NewHandler(monitorStore, logger),
		Pipeline:  pipelineHandler,
		FlowRun: func() *exec.Handler {
			h := exec.NewHandler(flowrunStore, runner, logger)
			h.WithContentDeps(contentStore, contentStore)
			return h
		}(),
		Upload: upload.NewHandler(s3Client, cfg.R2Bucket, cfg.R2PublicURL, logger),
		Feed:   feed.NewHandler(feedStore, feedCollector, logger),
		Notion: notionHandler,
		Tag:    tag.NewHandler(tagStore, pool, logger),
		NotionSource: func() *notion.SourceHandler {
			sh := notion.NewSourceHandler(notionSourceStore, notionClient, c.source, logger)
			sh.SetSyncer(notionHandler)
			return sh
		}(),
		Goal: goal.NewHandler(goalStore, logger),
		Task: task.NewHandler(taskStore, logger,
			task.WithNotion(
				&notionTaskAdapter{client: notionClient},
				&sourceDBResolver{store: notionSourceStore, cache: c.source},
			),
			task.WithProjectResolver(func(ctx context.Context, slug string) (uuid.UUID, string, error) {
				proj, err := projectStore.ProjectBySlug(ctx, slug)
				if err != nil {
					proj, err = projectStore.ProjectByAlias(ctx, slug)
				}
				if err != nil {
					proj, err = projectStore.ProjectByTitle(ctx, slug)
				}
				if err != nil {
					return uuid.UUID{}, "", fmt.Errorf("project %q not found", slug)
				}
				return proj.ID, proj.Title, nil
			}),
		),
		Stats:     stats.NewHandler(stats.NewStore(pool), logger),
		Learning:  learning.NewHandler(contentStore, projectStore, logger),
		Note:      note.NewHandler(noteStore, logger),
		Activity:  activity.NewHandler(activityStore, logger),
		Session:   session.NewHandler(sessionStore, logger),
		Reconcile: reconcile.NewHandler(reconcileStore, logger),
		Logger:    logger,
	}

	// sync on startup: catch anything missed while the server was down
	// Tracked by pipelineHandler.Wait() so graceful shutdown drains this work.
	pipelineHandler.Go(func() {
		syncCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		logger.Info("startup sync: starting")
		contentSync.SyncAllFromGitHub(syncCtx)
		notionHandler.SyncAll(syncCtx)
		logger.Info("startup sync: complete")
	})

	return server.Run(ctx, server.Config{
		Port:       cfg.Port,
		CORSOrigin: cfg.CORSOrigin,
		JWTSecret:  cfg.JWTSecret,
	}, &deps, logger)
}

// caches holds all Ristretto caches used by the application.
type caches struct {
	graph  *ristretto.Cache[string, *content.KnowledgeGraph]
	feed   *ristretto.Cache[string, []byte]
	topic  *ristretto.Cache[string, []topic.Topic]
	source *ristretto.Cache[string, string]
}

// createCaches creates all Ristretto v2 caches (TinyLFU admission, per-item TTL).
func createCaches() (*caches, error) {
	graphCache, err := ristretto.NewCache(&ristretto.Config[string, *content.KnowledgeGraph]{
		NumCounters: 10, // 10x expected items (1 key: "graph")
		MaxCost:     1,  // count-based: 1 item max
		BufferItems: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("creating graph cache: %w", err)
	}

	feedCache, err := ristretto.NewCache(&ristretto.Config[string, []byte]{
		NumCounters: 100,     // 10x expected items (2 keys: "rss", "sitemap")
		MaxCost:     1 << 20, // 1 MB byte budget
		BufferItems: 64,
	})
	if err != nil {
		graphCache.Close()
		return nil, fmt.Errorf("creating feed cache: %w", err)
	}

	topicCache, err := ristretto.NewCache(&ristretto.Config[string, []topic.Topic]{
		NumCounters: 10, // 10x expected items (1 key: "topics")
		MaxCost:     1,  // count-based: 1 item max
		BufferItems: 64,
	})
	if err != nil {
		graphCache.Close()
		feedCache.Close()
		return nil, fmt.Errorf("creating topic cache: %w", err)
	}

	sourceCache, err := ristretto.NewCache(&ristretto.Config[string, string]{
		NumCounters: 50, // 10x expected items (~4 sources)
		MaxCost:     10, // count-based: max 10 items
		BufferItems: 64,
	})
	if err != nil {
		graphCache.Close()
		feedCache.Close()
		topicCache.Close()
		return nil, fmt.Errorf("creating source cache: %w", err)
	}

	return &caches{
		graph:  graphCache,
		feed:   feedCache,
		topic:  topicCache,
		source: sourceCache,
	}, nil
}

// setupNotifiers creates a notifier from configured providers (LINE, Telegram)
// or falls back to noop.
func setupNotifiers(cfg *config, logger *slog.Logger) notify.Notifier {
	var notifiers []notify.Notifier
	if cfg.LINEChannelToken != "" && cfg.LINEUserID != "" {
		notifiers = append(notifiers, notify.NewLINE(cfg.LINEChannelToken, cfg.LINEUserID))
		logger.Info("notification: LINE enabled")
	}
	if cfg.TelegramBotToken != "" && cfg.TelegramChatID != "" {
		notifiers = append(notifiers, notify.NewTelegram(cfg.TelegramBotToken, cfg.TelegramChatID))
		logger.Info("notification: Telegram enabled")
	}
	if len(notifiers) > 0 {
		return notify.NewMulti(notifiers...)
	}
	logger.Info("notification: no providers configured, using noop")
	return notify.NewNoop(logger)
}

// aiDeps holds the dependencies needed to set up the AI pipeline.
type aiDeps struct {
	flowrunStore   *exec.Store
	contentStore   *content.Store
	reviewStore    *review.Store
	topicStore     *topic.Store
	collectedStore *entry.Store
	projectStore   *project.Store
	taskStore      *task.Store
	activityStore  *activity.Store
	githubFetcher  *pipeline.GitHub
	notifier       notify.Notifier
	tokenBudget    *budget.Budget
	taipeiLoc      *time.Location
	logger         *slog.Logger
}

// aiResult holds the outputs from AI pipeline setup.
type aiResult struct {
	runner       *exec.Runner
	noteEmbedder ai.Embedder    // nil in mock mode
	genkit       *genkit.Genkit // nil in mock mode
}

// setupAI initializes the AI pipeline in either mock or real mode.
func setupAI(ctx context.Context, cfg *config, d *aiDeps) (*aiResult, error) {
	alerter := exec.NewNotifyAlerter(d.notifier, d.logger)

	if cfg.MockMode {
		d.logger.Info("starting in MOCK MODE — AI calls disabled")
		registry := aiflow.NewRegistry(
			aiflow.NewMockContentReview(),
			aiflow.NewMockContentProofread(),
			aiflow.NewMockContentExcerpt(),
			aiflow.NewMockContentTags(),
			aiflow.NewMockContentPolish(),
			aiflow.NewMockDigestGenerate(),
			aiflow.NewMockBookmarkGenerate(),
			aiflow.NewMockMorningBrief(),
			aiflow.NewMockWeeklyReview(),
			aiflow.NewMockProjectTrack(),
			aiflow.NewMockContentStrategy(),
			aiflow.NewMockBuildLog(),
			aiflow.NewMockDailyDevLog(),
		)
		return &aiResult{
			runner: exec.New(d.flowrunStore, registry, 3, alerter, d.logger),
		}, nil
	}

	googleAI := &googlegenai.GoogleAI{}
	anthropicPlugin := &anthropic.Anthropic{}
	g := genkit.Init(ctx, genkit.WithPlugins(googleAI, anthropicPlugin))

	geminiModel, err := googleAI.DefineModel(g, cfg.GeminiModel, &ai.ModelOptions{
		Label: "Gemini Review",
		Supports: &ai.ModelSupports{
			Multiturn:  true,
			SystemRole: true,
			Media:      true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("defining gemini model: %w", err)
	}

	claudeModel, err := anthropicPlugin.DefineModel(g, cfg.ClaudeModel, &ai.ModelOptions{
		Label: "Claude Polish",
		Supports: &ai.ModelSupports{
			Multiturn:  true,
			SystemRole: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("defining claude model: %w", err)
	}

	embedder, err := googleAI.DefineEmbedder(g, "gemini-embedding-2-preview", &ai.EmbedderOptions{})
	if err != nil {
		return nil, fmt.Errorf("defining embedder: %w", err)
	}

	contentProofread := aiflow.NewContentProofread(g, geminiModel, d.logger)
	contentExcerpt := aiflow.NewContentExcerpt(g, geminiModel, d.logger)
	contentTags := aiflow.NewContentTags(g, geminiModel, d.logger)
	contentReview := aiflow.NewContentReview(
		g, embedder,
		d.contentStore, d.contentStore, d.contentStore, d.reviewStore, d.topicStore,
		contentProofread, contentExcerpt, contentTags,
		d.logger,
	)
	contentPolish := aiflow.NewContentPolish(g, claudeModel, d.contentStore, d.logger)
	digestGenerate := aiflow.NewDigestGenerate(g, geminiModel, d.contentStore, d.collectedStore, d.projectStore, d.tokenBudget, d.taipeiLoc, d.logger)
	bookmarkGenerate := aiflow.NewBookmarkGenerate(g, geminiModel, d.collectedStore, d.tokenBudget, d.logger)
	morningBrief := aiflow.NewMorningBrief(g, d.taskStore, d.notifier, d.taipeiLoc, d.logger)
	weeklyReview := aiflow.NewWeeklyReview(
		g, geminiModel, d.taskStore, d.taskStore,
		d.collectedStore, d.contentStore, d.projectStore, d.githubFetcher,
		d.notifier, d.tokenBudget, d.taipeiLoc, d.logger,
	)
	projectTrack := aiflow.NewProjectTrack(
		g, geminiModel, d.projectStore, d.projectStore,
		d.notifier, d.tokenBudget, d.logger,
	)
	contentStrategy := aiflow.NewContentStrategy(
		g, geminiModel, d.contentStore, d.collectedStore, d.projectStore,
		d.notifier, d.tokenBudget, d.taipeiLoc, d.logger,
	)
	buildLog := aiflow.NewBuildLog(
		g, geminiModel, d.projectStore, d.githubFetcher, d.contentStore,
		d.tokenBudget, d.taipeiLoc, d.logger,
	)
	dailyDevLog := aiflow.NewDailyDevLog(
		g, geminiModel, d.activityStore,
		d.notifier, d.tokenBudget, d.taipeiLoc, d.logger,
	)
	registry := aiflow.NewRegistry(
		contentReview, contentProofread, contentExcerpt, contentTags,
		contentPolish, digestGenerate, bookmarkGenerate,
		morningBrief, weeklyReview, projectTrack,
		contentStrategy, buildLog, dailyDevLog,
	)
	return &aiResult{
		runner:       exec.New(d.flowrunStore, registry, 3, alerter, d.logger),
		noteEmbedder: embedder,
		genkit:       g,
	}, nil
}

// cronDeps holds the dependencies needed to register cron jobs.
type cronDeps struct {
	flowrunStore   *exec.Store
	feedStore      *feed.Store
	authStore      *auth.Store
	collectedStore *entry.Store
	sessionStore   *session.Store
	activityStore  *activity.Store
	projectStore   *project.Store
	noteStore      *note.Store
	runner         *exec.Runner
	feedCollector  *collector.Collector
	notifier       notify.Notifier
	tokenBudget    *budget.Budget
	recon          *reconcile.Reconciler
	contentSync    *pipeline.ContentSync
	notionHandler  *notion.Handler
	noteEmbedder   ai.Embedder    // nil in mock mode
	genkitInstance *genkit.Genkit // nil in mock mode
	logger         *slog.Logger
}

// registerCronJobs registers all scheduled jobs on the given cron scheduler.
// appCtx is the application-level context tied to the shutdown signal; each job
// derives its own timeout from it so that in-flight work is cancelled on shutdown.
func registerCronJobs(scheduler *cron.Cron, d *cronDeps, appCtx context.Context) {
	addCron := func(schedule, name string, fn func()) {
		if _, err := scheduler.AddFunc(schedule, fn); err != nil {
			d.logger.Error("cron: failed to register", "job", name, "error", err)
		}
	}

	// flow retries (every 2 min)
	addCron("@every 2m", "retry-flows", retryFlows(appCtx, d.flowrunStore, d.runner, d.notifier, d.logger))

	// feed collection (overlap guarded)
	var collectRunning atomic.Bool
	collectFn := collectFeeds(appCtx, d.feedStore, d.feedCollector, &collectRunning, d.notifier, d.logger)
	addCron("0 */4 * * *", "feed-hourly_4", func() { collectFn(feed.ScheduleHourly4, "hourly_4") })
	addCron("0 6 * * *", "feed-daily", func() { collectFn(feed.ScheduleDaily, "daily") })
	addCron("0 6 * * 1", "feed-weekly", func() { collectFn(feed.ScheduleWeekly, "weekly") })

	// daily resets
	addCron("0 0 * * *", "budget-reset", resetBudget(d.tokenBudget, d.logger))
	addCron("0 1 * * *", "token-cleanup", cleanupExpiredTokens(appCtx, d.authStore, d.logger))

	// data retention cleanup — all follow the same pattern: delete old records, log count
	addCron("0 3 * * *", "retention-events", retentionFunc(appCtx,
		"deleted old activity events",
		func(ctx context.Context) (int64, error) {
			return d.activityStore.DeleteOldEvents(ctx, time.Now().AddDate(0, -12, 0))
		}, d.logger))
	addCron("15 3 * * *", "retention-ignored", retentionFunc(appCtx,
		"deleted old ignored collected data",
		func(ctx context.Context) (int64, error) {
			return d.collectedStore.DeleteOldIgnored(ctx, time.Now().AddDate(0, 0, -30))
		}, d.logger))
	addCron("30 3 * * *", "retention-flowruns", retentionFunc(appCtx,
		"deleted old completed flow runs",
		func(ctx context.Context) (int64, error) {
			return d.flowrunStore.DeleteOldCompletedRuns(ctx, time.Now().AddDate(0, 0, -90))
		}, d.logger))
	addCron("45 3 * * *", "retention-session-notes", retentionFunc(appCtx,
		"deleted old session notes",
		func(ctx context.Context) (int64, error) {
			return d.sessionStore.DeleteOldNotes(ctx,
				time.Now().AddDate(0, 0, -30),  // plan/reflection/context: 30 days
				time.Now().AddDate(0, 0, -365)) // metrics/insight: 365 days
		}, d.logger))

	// flow submissions
	for _, job := range []struct {
		schedule, flow string
		timeout        time.Duration
	}{
		{"30 7 * * *", "morning-brief", 2 * time.Minute},
		{"0 3 * * 1", "content-strategy", 3 * time.Minute},
		{"0 23 * * *", "daily-dev-log", 2 * time.Minute},
	} {
		addCron(job.schedule, job.flow, func() {
			ctx, cancel := context.WithTimeout(appCtx, job.timeout)
			defer cancel()
			if err := d.runner.Submit(ctx, job.flow, nil, nil); err != nil {
				d.logger.Error("cron: submitting flow", "flow", job.flow, "error", err)
			}
		})
	}

	// weekly review with health data (Monday 09:00)
	addCron("0 9 * * 1", "weekly-review", submitWeeklyReview(appCtx, d.flowrunStore, d.feedStore, d.runner, d.logger))

	// build-log generation (Monday 10:00)
	addCron("0 10 * * 1", "build-log-generate", submitBuildLogs(appCtx, d.projectStore, d.runner, d.logger))

	// reconciliation (Sunday 04:00)
	addCron("0 4 * * 0", "reconciliation", func() {
		ctx, cancel := context.WithTimeout(appCtx, 5*time.Minute)
		defer cancel()
		if err := d.recon.Run(ctx); err != nil {
			d.logger.Error("cron: reconciliation failed", "error", err)
			alertCron(d.notifier, d.logger, "reconciliation", err)
		}
	})

	// hourly full sync — GitHub + Notion (at :15 past each hour)
	var syncRunning atomic.Bool
	addCron("15 * * * *", "hourly-sync", func() {
		if !syncRunning.CompareAndSwap(false, true) {
			d.logger.Info("cron: skipping hourly sync, previous run still active")
			return
		}
		defer syncRunning.Store(false)
		ctx, cancel := context.WithTimeout(appCtx, 5*time.Minute)
		defer cancel()
		d.contentSync.SyncAllFromGitHub(ctx)
		d.notionHandler.SyncAll(ctx)
	})

	// note embedding generation (hourly at :30, after sync at :15)
	if d.noteEmbedder != nil {
		addCron("30 * * * *", "note-embedding", noteEmbeddingJob(appCtx, d.noteStore, d.noteEmbedder, d.genkitInstance, d.logger))
	}
}

// noteEmbeddingJob returns a cron function that generates embeddings for notes
// that don't have them yet.
func noteEmbeddingJob(appCtx context.Context, noteStore *note.Store, embedder ai.Embedder, g *genkit.Genkit, logger *slog.Logger) func() {
	return func() {
		ctx, cancel := context.WithTimeout(appCtx, 5*time.Minute)
		defer cancel()
		candidates, err := noteStore.NotesWithoutEmbedding(ctx, 20)
		if err != nil {
			logger.Error("cron: listing notes without embedding", "error", err)
			return
		}
		if len(candidates) == 0 {
			return
		}
		var embedded int
		for _, c := range candidates {
			if err := embedNote(ctx, noteStore, embedder, g, c); err != nil {
				logger.Error("cron: embedding note", "note_id", c.ID, "error", err)
				continue
			}
			embedded++
		}
		if embedded > 0 {
			logger.Info("cron: note embeddings generated", "count", embedded, "candidates", len(candidates))
		}
	}
}

// embedNote generates and stores the embedding for a single note candidate.
func embedNote(ctx context.Context, noteStore *note.Store, embedder ai.Embedder, g *genkit.Genkit, c note.EmbeddingCandidate) error {
	text := ""
	if c.Title != nil {
		text = *c.Title + "\n"
	}
	if c.ContentText != nil {
		text += *c.ContentText
	}
	if text == "" {
		return nil
	}
	resp, err := genkit.Embed(ctx, g,
		ai.WithEmbedder(embedder),
		ai.WithTextDocs(text),
		ai.WithConfig(&genai.EmbedContentConfig{
			OutputDimensionality: genai.Ptr[int32](768),
		}),
	)
	if err != nil {
		return fmt.Errorf("generating embedding: %w", err)
	}
	if len(resp.Embeddings) == 0 || len(resp.Embeddings[0].Embedding) == 0 {
		return nil
	}
	vec := pgvector.NewVector(resp.Embeddings[0].Embedding)
	if err := noteStore.UpdateEmbedding(ctx, c.ID, vec); err != nil {
		return fmt.Errorf("storing embedding: %w", err)
	}
	return nil
}

func loadConfig(logger *slog.Logger) config {
	cfg := config{
		Port:        envOr("SERVER_PORT", "8080"),
		CORSOrigin:  envOr("CORS_ORIGIN", "http://localhost:4200"),
		SiteURL:     envOr("SITE_URL", "http://localhost:8080"),
		GeminiModel: envOr("GEMINI_MODEL", "gemini-3-flash-preview"),
		ClaudeModel: envOr("CLAUDE_MODEL", "claude-sonnet-4-6"),
		MockMode:    os.Getenv("MOCK_MODE") == "true",
	}

	cfg.DatabaseURL = requireEnv("DATABASE_URL", logger)
	cfg.JWTSecret = requireEnv("JWT_SECRET", logger)

	cfg.GitHubWebhookSecret = requireEnv("GITHUB_WEBHOOK_SECRET", logger)
	cfg.GitHubToken = os.Getenv("GITHUB_TOKEN")
	cfg.GitHubRepo = envOr("GITHUB_REPO", "Koopa0/obsidian")
	cfg.GitHubBotLogin = os.Getenv("GITHUB_BOT_LOGIN")

	cfg.R2Endpoint = requireEnv("R2_ENDPOINT", logger)
	cfg.R2AccessKeyID = requireEnv("R2_ACCESS_KEY_ID", logger)
	cfg.R2SecretAccessKey = requireEnv("R2_SECRET_ACCESS_KEY", logger)
	cfg.R2Bucket = envOr("R2_BUCKET", "blog")
	cfg.R2PublicURL = requireEnv("R2_PUBLIC_URL", logger)

	// AI keys: required unless MOCK_MODE
	// googlegenai plugin reads GEMINI_API_KEY from env
	// anthropic plugin reads ANTHROPIC_API_KEY from env
	if !cfg.MockMode {
		requireEnv("GEMINI_API_KEY", logger)
		requireEnv("ANTHROPIC_API_KEY", logger)
	}

	// Notion integration (optional — empty means disabled)
	cfg.NotionAPIKey = os.Getenv("NOTION_API_KEY")
	cfg.NotionWebhookSecret = os.Getenv("NOTION_WEBHOOK_SECRET")

	// Google OAuth
	cfg.GoogleClientID = requireEnv("GOOGLE_CLIENT_ID", logger)
	cfg.GoogleClientSecret = requireEnv("GOOGLE_CLIENT_SECRET", logger)
	cfg.GoogleRedirectURI = requireEnv("GOOGLE_REDIRECT_URI", logger)
	cfg.AdminEmail = requireEnv("ADMIN_EMAIL", logger)

	// Notification providers (optional — empty means noop)
	cfg.LINEChannelToken = os.Getenv("LINE_CHANNEL_TOKEN")
	cfg.LINEUserID = os.Getenv("LINE_USER_ID")
	cfg.TelegramBotToken = os.Getenv("TELEGRAM_BOT_TOKEN")
	cfg.TelegramChatID = os.Getenv("TELEGRAM_CHAT_ID")

	return cfg
}

func runMigrations(databaseURL string, logger *slog.Logger) error {
	// Strip postgres:// or postgresql:// prefix and replace with pgx5://
	connStr := databaseURL
	if after, ok := strings.CutPrefix(connStr, "postgres://"); ok {
		connStr = "pgx5://" + after
	} else if after, ok := strings.CutPrefix(connStr, "postgresql://"); ok {
		connStr = "pgx5://" + after
	} else {
		return fmt.Errorf("unsupported database URL scheme: %s", connStr)
	}
	m, err := migrate.New("file://migrations", connStr)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}
	defer func() {
		srcErr, dbErr := m.Close()
		if srcErr != nil {
			logger.Error("closing migration source", "error", srcErr)
		}
		if dbErr != nil {
			logger.Error("closing migration db", "error", dbErr)
		}
	}()

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			logger.Info("migrations: no changes")
			return nil
		}
		return fmt.Errorf("applying migrations: %w", err)
	}

	logger.Info("migrations: applied successfully")
	return nil
}

func requireEnv(key string, logger *slog.Logger) string {
	v := os.Getenv(key)
	if v == "" {
		logger.Error(key + " is required")
		os.Exit(1)
	}
	return v
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// notionTaskAdapter adapts notion.Client to task.NotionClient.
// Lives in main.go because task and notion have a circular import
// (notion imports task), so only the wiring layer can bridge them.
type notionTaskAdapter struct {
	client *notion.Client
}

func (a *notionTaskAdapter) UpdatePageStatus(ctx context.Context, pageID, status string) error {
	return a.client.UpdatePageStatus(ctx, pageID, status)
}

func (a *notionTaskAdapter) UpdatePageProperties(ctx context.Context, pageID string, properties map[string]any) error {
	return a.client.UpdatePageProperties(ctx, pageID, properties)
}

func (a *notionTaskAdapter) CreateTaskPage(ctx context.Context, databaseID, title, dueDate, description string) (string, error) {
	return a.client.CreateTask(ctx, &notion.CreateTaskParams{
		DatabaseID:  databaseID,
		Title:       title,
		DueDate:     dueDate,
		Description: description,
	})
}

// sourceDBResolver adapts notion.Store + cache to task.DBIDResolver.
// Lives in main.go for the same reason as notionTaskAdapter: circular
// import between notion and task prevents placing it in either package.
type sourceDBResolver struct {
	store *notion.Store
	cache *ristretto.Cache[string, string]
}

func (r *sourceDBResolver) DatabaseIDByRole(ctx context.Context, role string) (string, error) {
	if id, ok := r.cache.Get("role:" + role); ok {
		return id, nil
	}
	src, err := r.store.SourceByRole(ctx, role)
	if err != nil {
		return "", err
	}
	r.cache.SetWithTTL("role:"+role, src.DatabaseID, 1, 10*time.Minute)
	return src.DatabaseID, nil
}
