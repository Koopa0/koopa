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

	genkitai "github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robfig/cron/v3"

	"github.com/koopa0/blog-backend/internal/activity"
	aiflow "github.com/koopa0/blog-backend/internal/ai"
	"github.com/koopa0/blog-backend/internal/ai/exec"
	aireport "github.com/koopa0/blog-backend/internal/ai/report"
	"github.com/koopa0/blog-backend/internal/auth"
	"github.com/koopa0/blog-backend/internal/budget"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/event"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/feed/collector"
	"github.com/koopa0/blog-backend/internal/feed/entry"
	"github.com/koopa0/blog-backend/internal/github"
	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/learning"
	"github.com/koopa0/blog-backend/internal/monitor"
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
	"github.com/koopa0/blog-backend/internal/upload"
	"github.com/koopa0/blog-backend/internal/webhook"
)

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
	entryStore := entry.NewStore(pool)
	monitorStore := monitor.NewStore(pool)
	execStore := exec.NewStore(pool)
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
	feedCollector := collector.New(entryStore, feedStore, monitorStore, logger)
	defer feedCollector.Stop()
	tokenBudget := budget.New(500_000)

	// notion source cache (shared between notion.Handler and notion.SourceHandler)
	sourceCache, err := notion.NewSourceCache()
	if err != nil {
		return err
	}
	defer sourceCache.Close()

	// upload
	s3Client := upload.NewS3Client(ctx, cfg.R2Endpoint, cfg.R2AccessKeyID, cfg.R2SecretAccessKey)

	// notification providers
	notifier := setupNotifiers(&cfg, logger)

	// wire notifier to feed store for auto-disable alerts
	feedStore.SetAlerts(notifier)

	// notion client (used by morning brief flow and webhook handler)
	notionClient := notion.NewClient(cfg.NotionAPIKey)

	// github client (used by weekly review flow and pipeline handler)
	githubFetcher := github.NewClient(cfg.GitHubToken, cfg.GitHubRepo)

	// AI pipeline — Genkit + flow registry
	aiRes, err := aiflow.Setup(ctx, aiflow.PipelineConfig{
		MockMode:    cfg.MockMode,
		GeminiModel: cfg.GeminiModel,
		ClaudeModel: cfg.ClaudeModel,
	}, aiflow.PipelineStores{
		Content: contentStore,
		Review:  reviewStore,
		Topic:   topicStore,
		Entry:   entryStore,
		Project: projectStore,
	}, aiflow.PipelineDeps{
		GitHub:      githubFetcher,
		Notifier:    notifier,
		TokenBudget: tokenBudget,
		Location:    taipeiLoc,
		Logger:      logger,
		ReportFlows: func(g *genkit.Genkit, model genkitai.Model) []aiflow.Flow {
			return []aiflow.Flow{
				aireport.NewDigest(g, model, aiflow.DigestSystemPrompt, contentStore, entryStore, projectStore, tokenBudget, taipeiLoc, logger),
				aireport.NewMorning(g, taskStore, notifier, taipeiLoc, logger),
				aireport.NewWeekly(g, model, aireport.WeeklyDeps{
					SystemPrompt:   aiflow.WeeklyReviewSystemPrompt,
					Tasks:          taskStore,
					TaskCompletion: taskStore,
					Collected:      entryStore,
					Contents:       contentStore,
					Projects:       projectStore,
					Commits:        githubFetcher,
					Notifier:       notifier,
					TokenBudget:    tokenBudget,
					Location:       taipeiLoc,
					Logger:         logger,
				}),
				aireport.NewDaily(g, model, aiflow.DailyDevLogSystemPrompt, activityStore, notifier, tokenBudget, taipeiLoc, logger),
			}
		},
	})
	if err != nil {
		return err
	}

	alerter := exec.NewNotifyAlerter(notifier, logger)
	runner := exec.New(execStore, aiRes.Registry, 3, alerter, logger)

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
		notionClient, notionSourceStore, sourceCache,
		runner, cfg.NotionWebhookSecret, logger,
		notion.WithDedup(webhookDedup),
		notion.WithEventRecorder(activityStore),
		notion.WithProjectResolver(projectStore),
		notion.WithGoalResolver(goalStore),
		notion.WithProjectSync(projectStore, func(ctx context.Context, input *notion.ProjectSyncInput) error {
			_, err := projectStore.SyncFromNotion(ctx, &project.SyncFromNotionInput{
				PageID:      input.PageID,
				Title:       input.Title,
				Status:      input.Status,
				Description: input.Description,
				Area:        input.Area,
				GoalID:      input.GoalID,
				Deadline:    input.Deadline,
			})
			return err
		}),
		notion.WithGoalSync(goalStore, func(ctx context.Context, input *notion.GoalSyncInput) error {
			_, err := goalStore.SyncFromNotion(ctx, &goal.SyncFromNotionInput{
				PageID:   input.PageID,
				Title:    input.Title,
				Status:   input.Status,
				Area:     input.Area,
				Deadline: input.Deadline,
			})
			return err
		}),
		notion.WithTaskSync(taskStore, func(ctx context.Context, input *notion.TaskSyncInput) error {
			return taskStore.SyncFromNotion(ctx, &task.SyncFromNotionInput{
				PageID:        input.PageID,
				Title:         input.Title,
				Status:        input.Status,
				Due:           input.Due,
				Energy:        input.Energy,
				Priority:      input.Priority,
				RecurInterval: input.RecurInterval,
				RecurUnit:     input.RecurUnit,
				MyDay:         input.MyDay,
				Description:   input.Description,
				ProjectPageID: input.ProjectPageID,
			}, projectStore)
		}),
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

	// note embedder (nil in mock mode)
	var noteEmbedder *note.Embedder
	if aiRes.Embedder != nil {
		noteEmbedder = note.NewEmbedder(noteStore, aiRes.Embedder, aiRes.Genkit, logger)
	}

	// cron: register all scheduled jobs
	cronScheduler := cron.New(cron.WithLocation(taipeiLoc))
	defer cronScheduler.Stop()
	registerCronJobs(cronScheduler, &cronDeps{
		execStore:     execStore,
		feedStore:     feedStore,
		authStore:     authStore,
		entryStore:    entryStore,
		sessionStore:  sessionStore,
		activityStore: activityStore,
		projectStore:  projectStore,
		noteStore:     noteStore,
		runner:        runner,
		feedCollector: feedCollector,
		notifier:      notifier,
		tokenBudget:   tokenBudget,
		recon:         recon,
		contentSync:   contentSync,
		notionHandler: notionHandler,
		noteEmbedder:  noteEmbedder,
		logger:        logger,
	}, ctx)
	cronScheduler.Start()

	handlers := server.Handlers{
		Pool: pool,
		Auth: auth.NewHandler(authStore, cfg.JWTSecret, &auth.GoogleConfig{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURI:  cfg.GoogleRedirectURI,
			AdminEmail:   cfg.AdminEmail,
			FrontendURL:  cfg.CORSOrigin,
		}, logger),
		Topic:    topic.NewHandler(topicStore, contentStore, logger),
		Content:  content.NewHandler(contentStore, cfg.SiteURL, logger),
		Project:  project.NewHandler(projectStore, logger),
		Review:   review.NewHandler(reviewStore, logger),
		Entry:    entry.NewHandler(entryStore, logger),
		Monitor:  monitor.NewHandler(monitorStore, logger),
		Pipeline: pipelineHandler,
		Exec: func() *exec.Handler {
			h := exec.NewHandler(execStore, runner, logger)
			h.WithContentDeps(contentStore, contentStore)
			return h
		}(),
		Upload: upload.NewHandler(s3Client, cfg.R2Bucket, cfg.R2PublicURL, logger),
		Feed:   feed.NewHandler(feedStore, feedCollector, logger),
		Notion: notionHandler,
		Tag:    tag.NewHandler(tagStore, pool, logger),
		NotionSource: func() *notion.SourceHandler {
			sh := notion.NewSourceHandler(notionSourceStore, notionClient, sourceCache, logger)
			sh.SetSyncer(notionHandler)
			return sh
		}(),
		Goal: goal.NewHandler(goalStore, logger),
		Task: task.NewHandler(taskStore, logger,
			task.WithNotion(notionClient, notionSourceStore),
			task.WithHTTPProjectResolver(func(ctx context.Context, slug string) (uuid.UUID, string, error) {
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
	}, &handlers, logger)
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

// cronDeps holds the dependencies needed to register cron jobs.
type cronDeps struct {
	execStore     *exec.Store
	feedStore     *feed.Store
	authStore     *auth.Store
	entryStore    *entry.Store
	sessionStore  *session.Store
	activityStore *activity.Store
	projectStore  *project.Store
	noteStore     *note.Store
	runner        *exec.Runner
	feedCollector *collector.Collector
	notifier      notify.Notifier
	tokenBudget   *budget.Budget
	recon         *reconcile.Reconciler
	contentSync   *pipeline.ContentSync
	notionHandler *notion.Handler
	noteEmbedder  *note.Embedder // nil in mock mode
	logger        *slog.Logger
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
	addCron("@every 2m", "retry-flows", retryFlows(appCtx, d.execStore, d.runner, d.notifier, d.logger))

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
			return d.entryStore.DeleteOldIgnored(ctx, time.Now().AddDate(0, 0, -30))
		}, d.logger))
	addCron("30 3 * * *", "retention-flowruns", retentionFunc(appCtx,
		"deleted old completed flow runs",
		func(ctx context.Context) (int64, error) {
			return d.execStore.DeleteOldCompletedRuns(ctx, time.Now().AddDate(0, 0, -90))
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
	addCron("0 9 * * 1", "weekly-review", submitWeeklyReview(appCtx, d.execStore, d.feedStore, d.runner, d.logger))

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
		addCron("30 * * * *", "note-embedding", func() {
			ctx, cancel := context.WithTimeout(appCtx, 5*time.Minute)
			defer cancel()
			n, err := d.noteEmbedder.EmbedMissing(ctx, 20)
			if err != nil {
				d.logger.Error("cron: note embedding", "error", err)
				return
			}
			if n > 0 {
				d.logger.Info("cron: note embeddings generated", "count", n)
			}
		})
	}
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
