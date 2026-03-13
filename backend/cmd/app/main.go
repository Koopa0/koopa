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

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/anthropic"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robfig/cron/v3"

	"github.com/koopa0/blog-backend/internal/auth"
	"github.com/koopa0/blog-backend/internal/budget"
	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/collector"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/flow"
	"github.com/koopa0/blog-backend/internal/flowrun"
	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/notify"
	"github.com/koopa0/blog-backend/internal/notion"
	"github.com/koopa0/blog-backend/internal/pipeline"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/reconcile"
	"github.com/koopa0/blog-backend/internal/review"
	"github.com/koopa0/blog-backend/internal/server"
	"github.com/koopa0/blog-backend/internal/topic"
	"github.com/koopa0/blog-backend/internal/tracking"
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
	R2Endpoint          string
	R2AccessKeyID       string
	R2SecretAccessKey   string
	R2Bucket            string
	R2PublicURL         string
	GeminiModel         string
	ClaudeModel         string
	NotionAPIKey        string
	NotionWebhookSecret string
	NotionProjectsDB    string
	NotionTasksDB       string
	NotionBooksDB       string
	NotionGoalsDB       string
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

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}
	logger.Info("database connected")

	if err := runMigrations(cfg.DatabaseURL, logger); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}

	// stores
	authStore := auth.NewStore(pool)
	topicStore := topic.NewStore(pool)
	contentStore := content.NewStore(pool)
	projectStore := project.NewStore(pool)
	reviewStore := review.NewStore(pool)
	collectedStore := collected.NewStore(pool)
	trackingStore := tracking.NewStore(pool)
	flowrunStore := flowrun.NewStore(pool)
	feedStore := feed.NewStore(pool, logger)
	goalStore := goal.NewStore(pool)

	// timezone: all flows and cron jobs run in Asia/Taipei
	taipeiLoc, err := time.LoadLocation("Asia/Taipei")
	if err != nil {
		return fmt.Errorf("loading Asia/Taipei timezone: %w", err)
	}

	// collector + budget
	feedCollector := collector.New(collectedStore, feedStore, logger)
	tokenBudget := budget.New(500_000)

	// upload
	s3Client := upload.NewS3Client(ctx, cfg.R2Endpoint, cfg.R2AccessKeyID, cfg.R2SecretAccessKey)

	// notification providers
	var notifiers []notify.Notifier
	if cfg.LINEChannelToken != "" && cfg.LINEUserID != "" {
		notifiers = append(notifiers, notify.NewLINE(cfg.LINEChannelToken, cfg.LINEUserID))
		logger.Info("notification: LINE enabled")
	}
	if cfg.TelegramBotToken != "" && cfg.TelegramChatID != "" {
		notifiers = append(notifiers, notify.NewTelegram(cfg.TelegramBotToken, cfg.TelegramChatID))
		logger.Info("notification: Telegram enabled")
	}
	var notifier notify.Notifier
	if len(notifiers) > 0 {
		notifier = notify.NewMulti(notifiers...)
	} else {
		notifier = notify.NewNoop(logger)
		logger.Info("notification: no providers configured, using noop")
	}

	// wire notifier to feed store for auto-disable alerts
	feedStore.SetAlerts(notifier)

	// notion client (used by morning brief flow and webhook handler)
	notionClient := notion.NewClient(cfg.NotionAPIKey)

	// github client (used by weekly review flow and pipeline handler)
	githubFetcher := pipeline.NewGitHub(cfg.GitHubToken, cfg.GitHubRepo)

	// AI pipeline — Genkit + flow registry + runner
	alerter := &notifyAlerter{notifier: notifier, logger: logger}
	var runner *flowrun.Runner
	if cfg.MockMode {
		logger.Info("starting in MOCK MODE — AI calls disabled")
		registry := flow.NewRegistry(
			flow.NewMockContentReview(),
			flow.NewMockContentPolish(),
			flow.NewMockDigestGenerate(),
			flow.NewMockBookmarkGenerate(),
			flow.NewMockMorningBrief(),
			flow.NewMockWeeklyReview(),
			flow.NewMockProjectTrack(),
			flow.NewMockContentStrategy(),
			flow.NewMockBuildLog(),
		)
		runner = flowrun.New(flowrunStore, registry, 3, alerter, logger)
	} else {
		googleAI := &googlegenai.GoogleAI{}
		anthropicPlugin := &anthropic.Anthropic{}
		g := genkit.Init(ctx, genkit.WithPlugins(googleAI, anthropicPlugin))

		geminiModel, modelErr := googleAI.DefineModel(g, cfg.GeminiModel, &ai.ModelOptions{
			Label: "Gemini Review",
			Supports: &ai.ModelSupports{
				Multiturn:  true,
				SystemRole: true,
				Media:      true,
			},
		})
		if modelErr != nil {
			return fmt.Errorf("defining gemini model: %w", modelErr)
		}

		claudeModel, modelErr := anthropicPlugin.DefineModel(g, cfg.ClaudeModel, &ai.ModelOptions{
			Label: "Claude Polish",
			Supports: &ai.ModelSupports{
				Multiturn:  true,
				SystemRole: true,
			},
		})
		if modelErr != nil {
			return fmt.Errorf("defining claude model: %w", modelErr)
		}

		embedder, embedErr := googleAI.DefineEmbedder(g, "gemini-embedding-2-preview", &ai.EmbedderOptions{})
		if embedErr != nil {
			return fmt.Errorf("defining embedder: %w", embedErr)
		}

		contentReview := flow.NewContentReview(
			g, geminiModel, embedder,
			contentStore, contentStore, contentStore, reviewStore, topicStore,
			logger,
		)
		contentPolish := flow.NewContentPolish(g, claudeModel, contentStore, logger)
		digestGenerate := flow.NewDigestGenerate(g, geminiModel, contentStore, collectedStore, projectStore, tokenBudget, taipeiLoc, logger)
		bookmarkGenerate := flow.NewBookmarkGenerate(g, geminiModel, collectedStore, tokenBudget, logger)
		notionTasks := notion.NewTaskDB(notionClient, cfg.NotionTasksDB)
		morningBrief := flow.NewMorningBrief(
			g, geminiModel, notionTasks,
			collectedStore, contentStore, notifier, tokenBudget, taipeiLoc, logger,
		)
		weeklyReview := flow.NewWeeklyReview(
			g, geminiModel, notionTasks,
			collectedStore, contentStore, projectStore, githubFetcher,
			notifier, tokenBudget, taipeiLoc, logger,
		)
		projectTrack := flow.NewProjectTrack(
			g, geminiModel, projectStore, projectStore,
			notifier, tokenBudget, logger,
		)
		contentStrategy := flow.NewContentStrategy(
			g, geminiModel, contentStore, collectedStore, projectStore,
			notifier, tokenBudget, taipeiLoc, logger,
		)
		buildLog := flow.NewBuildLog(
			g, geminiModel, projectStore, githubFetcher, contentStore,
			tokenBudget, taipeiLoc, logger,
		)
		registry := flow.NewRegistry(contentReview, contentPolish, digestGenerate, bookmarkGenerate, morningBrief, weeklyReview, projectTrack, contentStrategy, buildLog)
		runner = flowrun.New(flowrunStore, registry, 3, alerter, logger)
	}

	runner.Start(ctx)
	defer runner.Stop()

	// cron: all jobs run in Asia/Taipei timezone
	cronScheduler := cron.New(cron.WithLocation(taipeiLoc))

	// cron: retry failed/stuck flow runs every 2 minutes
	_, err = cronScheduler.AddFunc("@every 2m", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		runs, retryErr := flowrunStore.RetryableRuns(ctx)
		if retryErr != nil {
			logger.Error("cron: scanning retryable flow runs", "error", retryErr)
			return
		}
		for _, r := range runs {
			runner.Requeue(r.ID)
		}
		if len(runs) > 0 {
			logger.Info("cron: requeued flow runs", "count", len(runs))
		}
	})
	if err != nil {
		return fmt.Errorf("adding cron job: %w", err)
	}

	// overlap guard for feed collection cron jobs
	var collectRunning atomic.Bool

	// collectFeedsCron runs feed collection with timeout and overlap protection.
	collectFeedsCron := func(schedule, label string) {
		if !collectRunning.CompareAndSwap(false, true) {
			logger.Info("cron: skipping " + label + ", previous run still active")
			return
		}
		defer collectRunning.Store(false)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		feeds, feedErr := feedStore.EnabledFeedsBySchedule(ctx, schedule)
		if feedErr != nil {
			logger.Error("cron: listing "+label+" feeds", "error", feedErr)
			return
		}
		var totalNew int
		for _, f := range feeds {
			ids, fetchErr := feedCollector.FetchFeed(ctx, f)
			if fetchErr != nil {
				logger.Error("cron: collecting feed", "feed_id", f.ID, "error", fetchErr)
				continue
			}
			totalNew += len(ids)
		}
		if len(feeds) > 0 {
			logger.Info("cron: "+label+" collect complete", "feeds", len(feeds), "new_items", totalNew)
		}
	}

	// cron: collect feeds every 4 hours (hourly_4 schedule)
	_, err = cronScheduler.AddFunc("0 */4 * * *", func() {
		collectFeedsCron(feed.ScheduleHourly4, "hourly_4")
	})
	if err != nil {
		return fmt.Errorf("adding hourly_4 cron job: %w", err)
	}

	// cron: collect daily feeds at 06:00 (Asia/Taipei)
	_, err = cronScheduler.AddFunc("0 6 * * *", func() {
		collectFeedsCron(feed.ScheduleDaily, "daily")
	})
	if err != nil {
		return fmt.Errorf("adding daily cron job: %w", err)
	}

	// cron: collect weekly feeds at 06:00 Monday (Asia/Taipei)
	_, err = cronScheduler.AddFunc("0 6 * * 1", func() {
		collectFeedsCron(feed.ScheduleWeekly, "weekly")
	})
	if err != nil {
		return fmt.Errorf("adding weekly cron job: %w", err)
	}

	// cron: reset token budget at midnight (Asia/Taipei)
	_, err = cronScheduler.AddFunc("0 0 * * *", func() {
		tokenBudget.Reset()
		logger.Info("cron: daily token budget reset")
	})
	if err != nil {
		return fmt.Errorf("adding budget reset cron job: %w", err)
	}

	// cron: clean up expired refresh tokens at 01:00 (Asia/Taipei)
	_, err = cronScheduler.AddFunc("0 1 * * *", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if delErr := authStore.DeleteExpiredTokens(ctx); delErr != nil {
			logger.Error("cron: deleting expired tokens", "error", delErr)
		} else {
			logger.Info("cron: expired tokens cleaned up")
		}
	})
	if err != nil {
		return fmt.Errorf("adding token cleanup cron job: %w", err)
	}

	// cron: morning brief at 07:30 (Asia/Taipei)
	_, err = cronScheduler.AddFunc("30 7 * * *", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if submitErr := runner.Submit(ctx, "morning-brief", nil, nil); submitErr != nil {
			logger.Error("cron: submitting morning brief", "error", submitErr)
		}
	})
	if err != nil {
		return fmt.Errorf("adding morning brief cron job: %w", err)
	}

	// cron: weekly review at 09:00 Monday (Asia/Taipei)
	_, err = cronScheduler.AddFunc("0 9 * * 1", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if submitErr := runner.Submit(ctx, "weekly-review", nil, nil); submitErr != nil {
			logger.Error("cron: submitting weekly review", "error", submitErr)
		}
	})
	if err != nil {
		return fmt.Errorf("adding weekly review cron job: %w", err)
	}

	// cron: content strategy at 03:00 Monday (Asia/Taipei)
	_, err = cronScheduler.AddFunc("0 3 * * 1", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if submitErr := runner.Submit(ctx, "content-strategy", nil, nil); submitErr != nil {
			logger.Error("cron: submitting content strategy", "error", submitErr)
		}
	})
	if err != nil {
		return fmt.Errorf("adding content strategy cron job: %w", err)
	}

	// reconciler: weekly Obsidian + Notion comparison
	recon := reconcile.New(
		githubFetcher, contentStore,
		projectStore, goalStore,
		notionClient, notifier,
		reconcile.Config{
			NotionProjectsDB: cfg.NotionProjectsDB,
			NotionGoalsDB:    cfg.NotionGoalsDB,
		},
		logger,
	)

	// cron: reconciliation at 04:00 Sunday (Asia/Taipei)
	_, err = cronScheduler.AddFunc("0 4 * * 0", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if reconErr := recon.Run(ctx); reconErr != nil {
			logger.Error("cron: reconciliation failed", "error", reconErr)
		}
	})
	if err != nil {
		return fmt.Errorf("adding reconciliation cron job: %w", err)
	}

	cronScheduler.Start()
	defer cronScheduler.Stop()

	// webhook replay protection: shared dedup cache with 10-minute TTL
	webhookDedup := webhook.NewDeduplicationCache(10 * time.Minute)
	defer webhookDedup.Stop()

	// notion webhook handler
	notionHandler := notion.NewHandler(notionClient, projectStore, goalStore, runner, notion.Config{
		APIKey:        cfg.NotionAPIKey,
		WebhookSecret: cfg.NotionWebhookSecret,
		ProjectsDB:    cfg.NotionProjectsDB,
		TasksDB:       cfg.NotionTasksDB,
		BooksDB:       cfg.NotionBooksDB,
		GoalsDB:       cfg.NotionGoalsDB,
	}, logger)
	notionHandler.SetDedup(webhookDedup)

	// pipeline dependencies
	topicLookup := pipeline.NewTopicLookup(func(ctx context.Context, slug string) (uuid.UUID, error) {
		t, err := topicStore.TopicBySlug(ctx, slug)
		if err != nil {
			return uuid.UUID{}, err
		}
		return t.ID, nil
	})

	// pipeline handler with collector and reconciler
	pipelineHandler := pipeline.NewHandler(contentStore, contentStore, topicLookup, githubFetcher, runner, cfg.GitHubWebhookSecret, cfg.GitHubRepo, logger)
	defer pipelineHandler.Wait() // drain in-flight background operations before exit
	pipelineHandler.SetCollector(feedCollector, feedStore)
	pipelineHandler.SetReconciler(recon)
	pipelineHandler.SetNotionSync(notionHandler)
	pipelineHandler.SetDedup(webhookDedup)

	// flow admin handler
	flowHandler := flow.NewHandler(
		runner,
		&runReader{store: flowrunStore},
		contentStore,
		contentStore,
		logger,
	)

	// cron: hourly full sync — GitHub Obsidian content + Notion projects/goals
	// Safety net for missed webhooks; runs at :15 past each hour.
	_, err = cronScheduler.AddFunc("15 * * * *", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		pipelineHandler.SyncAllFromGitHub(ctx)
		notionHandler.SyncAll(ctx)
	})
	if err != nil {
		return fmt.Errorf("adding hourly sync cron job: %w", err)
	}

	deps := server.Deps{
		Pool: pool,
		Auth: auth.NewHandler(authStore, cfg.JWTSecret, auth.GoogleConfig{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURI:  cfg.GoogleRedirectURI,
			AdminEmail:   cfg.AdminEmail,
			FrontendURL:  cfg.CORSOrigin,
		}, logger),
		Topic:     topic.NewHandler(topicStore, contentStore, logger),
		Content:   content.NewHandler(contentStore, cfg.SiteURL, logger),
		Project:   project.NewHandler(projectStore, logger),
		Review:    review.NewHandler(reviewStore, logger),
		Collected: collected.NewHandler(collectedStore, logger),
		Tracking:  tracking.NewHandler(trackingStore, logger),
		Pipeline:  pipelineHandler,
		FlowRun:   flowrun.NewHandler(flowrunStore, runner, logger),
		Upload:    upload.NewHandler(s3Client, cfg.R2Bucket, cfg.R2PublicURL, logger),
		Flow:      flowHandler,
		Feed:      feed.NewHandler(feedStore, feedCollector, logger),
		Notion:    notionHandler,
		Logger:    logger,
	}

	// sync on startup: catch anything missed while the server was down
	// Tracked by pipelineHandler.Wait() so graceful shutdown drains this work.
	pipelineHandler.Go(func() {
		syncCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		logger.Info("startup sync: starting")
		pipelineHandler.SyncAllFromGitHub(syncCtx)
		notionHandler.SyncAll(syncCtx)
		logger.Info("startup sync: complete")
	})

	return server.Run(ctx, server.Config{
		Port:       cfg.Port,
		CORSOrigin: cfg.CORSOrigin,
		JWTSecret:  cfg.JWTSecret,
	}, deps, logger)
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
	cfg.NotionProjectsDB = os.Getenv("NOTION_PROJECTS_DB")
	cfg.NotionTasksDB = os.Getenv("NOTION_TASKS_DB")
	cfg.NotionBooksDB = os.Getenv("NOTION_BOOKS_DB")
	cfg.NotionGoalsDB = os.Getenv("NOTION_GOALS_DB")

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

// runReader converts flowrun.Run to flow.RunResult, breaking the flow ↔ flowrun import cycle.
type runReader struct {
	store *flowrun.Store
}

func (a *runReader) RunResult(ctx context.Context, id uuid.UUID) (*flow.RunResult, error) {
	run, err := a.store.Run(ctx, id)
	if err != nil {
		if errors.Is(err, flowrun.ErrNotFound) {
			return nil, flow.ErrNotFound
		}
		return nil, err
	}
	return toRunResult(run), nil
}

func (a *runReader) LatestCompletedRunResult(ctx context.Context, flowName string, contentID uuid.UUID) (*flow.RunResult, error) {
	run, err := a.store.LatestCompletedRun(ctx, flowName, contentID)
	if err != nil {
		if errors.Is(err, flowrun.ErrNotFound) {
			return nil, flow.ErrNotFound
		}
		return nil, err
	}
	return toRunResult(run), nil
}

func toRunResult(r *flowrun.Run) *flow.RunResult {
	return &flow.RunResult{
		ID:        r.ID,
		FlowName:  r.FlowName,
		ContentID: r.ContentID,
		Status:    string(r.Status),
		Output:    r.Output,
		EndedAt:   r.EndedAt,
	}
}

// notifyAlerter adapts notify.Notifier to flowrun.Alerter.
type notifyAlerter struct {
	notifier notify.Notifier
	logger   *slog.Logger
}

func (a *notifyAlerter) Alert(ctx context.Context, run flowrun.Run) error {
	errMsg := ""
	if run.Error != nil {
		errMsg = *run.Error
	}
	text := fmt.Sprintf("[ALERT] Flow run failed\nFlow: %s\nRun ID: %s\nAttempt: %d\nError: %s",
		run.FlowName, run.ID, run.Attempt, errMsg)

	if err := a.notifier.Send(ctx, text); err != nil {
		a.logger.Error("sending flow alert notification", "run_id", run.ID, "error", err)
		return err
	}
	return nil
}
