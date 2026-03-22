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
	"github.com/robfig/cron/v3"
	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/anthropic"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	pgvector "github.com/pgvector/pgvector-go"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/auth"
	"github.com/koopa0/blog-backend/internal/budget"
	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/collector"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/flow"
	"github.com/koopa0/blog-backend/internal/flowrun"
	"github.com/koopa0/blog-backend/internal/goal"
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
	feedCollector := collector.New(collectedStore, feedStore, trackingStore, logger)
	defer feedCollector.Stop()
	tokenBudget := budget.New(500_000)

	// caches (Ristretto v2 — TinyLFU admission, per-item TTL)
	// Cost model: count-based (1 item max) for single-key caches.
	graphCache, err := ristretto.NewCache(&ristretto.Config[string, *content.KnowledgeGraph]{
		NumCounters: 10, // 10× expected items (1 key: "graph")
		MaxCost:     1,  // count-based: 1 item max
		BufferItems: 64,
	})
	if err != nil {
		return fmt.Errorf("creating graph cache: %w", err)
	}
	defer graphCache.Close()

	// Cost model: byte-based for serialized XML payloads (rss, sitemap).
	feedCache, err := ristretto.NewCache(&ristretto.Config[string, []byte]{
		NumCounters: 100,     // 10× expected items (2 keys: "rss", "sitemap")
		MaxCost:     1 << 20, // 1 MB byte budget
		BufferItems: 64,
	})
	if err != nil {
		return fmt.Errorf("creating feed cache: %w", err)
	}
	defer feedCache.Close()

	// Cost model: count-based (1 item max) for single-key cache.
	topicCache, err := ristretto.NewCache(&ristretto.Config[string, []topic.Topic]{
		NumCounters: 10, // 10× expected items (1 key: "topics")
		MaxCost:     1,  // count-based: 1 item max
		BufferItems: 64,
	})
	if err != nil {
		return fmt.Errorf("creating topic cache: %w", err)
	}
	defer topicCache.Close()

	// Cost model: count-based for notion source role lookup (max ~10 entries).
	sourceCache, err := ristretto.NewCache(&ristretto.Config[string, string]{
		NumCounters: 50, // 10× expected items (~4 sources)
		MaxCost:     10, // count-based: max 10 items
		BufferItems: 64,
	})
	if err != nil {
		return fmt.Errorf("creating source cache: %w", err)
	}
	defer sourceCache.Close()

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
	var g *genkit.Genkit
	var noteEmbedder ai.Embedder // set when not in mock mode
	if cfg.MockMode {
		logger.Info("starting in MOCK MODE — AI calls disabled")
		registry := flow.NewRegistry(
			flow.NewMockContentReview(),
			flow.NewMockContentProofread(),
			flow.NewMockContentExcerpt(),
			flow.NewMockContentTags(),
			flow.NewMockContentPolish(),
			flow.NewMockDigestGenerate(),
			flow.NewMockBookmarkGenerate(),
			flow.NewMockMorningBrief(),
			flow.NewMockWeeklyReview(),
			flow.NewMockProjectTrack(),
			flow.NewMockContentStrategy(),
			flow.NewMockBuildLog(),
			flow.NewMockDailyDevLog(),
		)
		runner = flowrun.New(flowrunStore, registry, 3, alerter, logger)
	} else {
		googleAI := &googlegenai.GoogleAI{}
		anthropicPlugin := &anthropic.Anthropic{}
		g = genkit.Init(ctx, genkit.WithPlugins(googleAI, anthropicPlugin))

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
		noteEmbedder = embedder

		contentProofread := flow.NewContentProofread(g, geminiModel, logger)
		contentExcerpt := flow.NewContentExcerpt(g, geminiModel, logger)
		contentTags := flow.NewContentTags(g, geminiModel, logger)
		contentReview := flow.NewContentReview(
			g, embedder,
			contentStore, contentStore, contentStore, reviewStore, topicStore,
			contentProofread, contentExcerpt, contentTags,
			logger,
		)
		contentPolish := flow.NewContentPolish(g, claudeModel, contentStore, logger)
		digestGenerate := flow.NewDigestGenerate(g, geminiModel, contentStore, collectedStore, projectStore, tokenBudget, taipeiLoc, logger)
		bookmarkGenerate := flow.NewBookmarkGenerate(g, geminiModel, collectedStore, tokenBudget, logger)
		morningBrief := flow.NewMorningBrief(g, taskStore, notifier, taipeiLoc, logger)
		weeklyReview := flow.NewWeeklyReview(
			g, geminiModel, taskStore, taskStore,
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
		dailyDevLog := flow.NewDailyDevLog(
			g, geminiModel, activityStore,
			notifier, tokenBudget, taipeiLoc, logger,
		)
		registry := flow.NewRegistry(
			contentReview, contentProofread, contentExcerpt, contentTags,
			contentPolish, digestGenerate, bookmarkGenerate,
			morningBrief, weeklyReview, projectTrack,
			contentStrategy, buildLog, dailyDevLog,
		)
		runner = flowrun.New(flowrunStore, registry, 3, alerter, logger)
	}

	bizMetrics := server.NewMetrics()
	runner.SetObserver(&flowObserver{m: bizMetrics})
	runner.Start(ctx)
	defer runner.Stop()

	// reconciler: weekly Obsidian + Notion comparison
	recon := reconcile.New(
		githubFetcher, contentStore,
		projectStore, goalStore,
		notionClient, notifier,
		notionSourceStore,
		logger,
	)

	// webhook replay protection: shared dedup cache with 10-minute TTL
	webhookDedup := webhook.NewDeduplicationCache(10 * time.Minute)
	defer webhookDedup.Stop()

	// notion webhook handler
	notionHandler := notion.NewHandler(
		notionClient, notionSourceStore, sourceCache,
		projectStore, goalStore, taskStore, runner,
		cfg.NotionWebhookSecret, logger,
		notion.WithDedup(webhookDedup),
		notion.WithEventRecorder(activityStore),
		notion.WithProjectSlugResolver(projectStore),
		notion.WithProjectIDResolver(projectStore),
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

	// pipeline handler with collector and reconciler
	pipelineHandler := pipeline.NewHandler(pool, contentStore, contentStore, topicLookup, githubFetcher, runner, cfg.GitHubWebhookSecret, cfg.GitHubRepo, cfg.GitHubBotLogin, logger)
	defer pipelineHandler.Wait() // drain in-flight background operations before exit
	pipelineHandler.SetCollector(feedCollector, feedStore)
	pipelineHandler.SetReconciler(recon)
	pipelineHandler.SetNotionSync(notionHandler)
	noteStore := note.NewStore(pool)
	pipelineHandler.SetNoteSync(noteStore, tagStore)
	pipelineHandler.SetActivityRecorder(activityStore, githubFetcher)
	pipelineHandler.SetNoteEventRecorder(activityStore)
	pipelineHandler.SetProjectRepoResolver(projectStore)
	pipelineHandler.SetNoteLinkSync(noteStore)
	pipelineHandler.SetNotionTaskUpdater(notionClient)
	pipelineHandler.SetDedup(webhookDedup)

	// flow admin handler
	flowHandler := flow.NewHandler(
		runner,
		&runReader{store: flowrunStore},
		contentStore,
		contentStore,
		logger,
	)

	// cron: register all scheduled jobs
	cronScheduler := cron.New(cron.WithLocation(taipeiLoc))
	defer cronScheduler.Stop()

	addCron := func(schedule, name string, fn func()) {
		if _, err := cronScheduler.AddFunc(schedule, fn); err != nil {
			logger.Error("cron: failed to register", "job", name, "error", err)
		}
	}

	// flow retries (every 2 min)
	addCron("@every 2m", "retry-flows", retryFlows(flowrunStore, runner, notifier, logger))

	// feed collection (overlap guarded)
	var collectRunning atomic.Bool
	collectFn := collectFeeds(feedStore, feedCollector, &collectRunning, notifier, logger)
	addCron("0 */4 * * *", "feed-hourly_4", func() { collectFn(feed.ScheduleHourly4, "hourly_4") })
	addCron("0 6 * * *", "feed-daily", func() { collectFn(feed.ScheduleDaily, "daily") })
	addCron("0 6 * * 1", "feed-weekly", func() { collectFn(feed.ScheduleWeekly, "weekly") })

	// daily resets
	addCron("0 0 * * *", "budget-reset", func() {
		tokenBudget.Reset()
		logger.Info("cron: daily token budget reset")
	})
	addCron("0 1 * * *", "token-cleanup", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := authStore.DeleteExpiredTokens(ctx); err != nil {
			logger.Error("cron: deleting expired tokens", "error", err)
		}
	})

	// data retention cleanup
	addCron("0 3 * * *", "retention-events", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		cutoff := time.Now().AddDate(0, -12, 0)
		if n, err := activityStore.DeleteOldEvents(ctx, cutoff); err != nil {
			logger.Error("cron: deleting old activity events", "error", err)
		} else if n > 0 {
			logger.Info("cron: deleted old activity events", "count", n)
		}
	})
	addCron("15 3 * * *", "retention-ignored", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		cutoff := time.Now().AddDate(0, 0, -30)
		if n, err := collectedStore.DeleteOldIgnored(ctx, cutoff); err != nil {
			logger.Error("cron: deleting old ignored collected data", "error", err)
		} else if n > 0 {
			logger.Info("cron: deleted old ignored collected data", "count", n)
		}
	})
	addCron("30 3 * * *", "retention-flowruns", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		cutoff := time.Now().AddDate(0, 0, -90)
		if n, err := flowrunStore.DeleteOldCompletedRuns(ctx, cutoff); err != nil {
			logger.Error("cron: deleting old completed flow runs", "error", err)
		} else if n > 0 {
			logger.Info("cron: deleted old completed flow runs", "count", n)
		}
	})
	addCron("45 3 * * *", "retention-session-notes", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		cutoff := time.Now().AddDate(0, 0, -30)
		if n, err := sessionStore.DeleteOldNotes(ctx, cutoff); err != nil {
			logger.Error("cron: deleting old session notes", "error", err)
		} else if n > 0 {
			logger.Info("cron: deleted old session notes", "count", n)
		}
	})

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
			ctx, cancel := context.WithTimeout(context.Background(), job.timeout)
			defer cancel()
			if err := runner.Submit(ctx, job.flow, nil, nil); err != nil {
				logger.Error("cron: submitting flow", "flow", job.flow, "error", err)
			}
		})
	}

	// weekly review with health data (Monday 09:00)
	addCron("0 9 * * 1", "weekly-review", submitWeeklyReview(flowrunStore, feedStore, runner, logger))

	// build-log generation (Monday 10:00)
	addCron("0 10 * * 1", "build-log-generate", submitBuildLogs(projectStore, runner, logger))

	// reconciliation (Sunday 04:00)
	addCron("0 4 * * 0", "reconciliation", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := recon.Run(ctx); err != nil {
			logger.Error("cron: reconciliation failed", "error", err)
			alertCron(notifier, logger, "reconciliation", err)
		}
	})

	// hourly full sync — GitHub + Notion (at :15 past each hour)
	var syncRunning atomic.Bool
	addCron("15 * * * *", "hourly-sync", func() {
		if !syncRunning.CompareAndSwap(false, true) {
			logger.Info("cron: skipping hourly sync, previous run still active")
			return
		}
		defer syncRunning.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		pipelineHandler.SyncAllFromGitHub(ctx)
		notionHandler.SyncAll(ctx)
	})

	// note embedding generation (hourly at :30, after sync at :15)
	if noteEmbedder != nil {
		addCron("30 * * * *", "note-embedding", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
				text := ""
				if c.Title != nil {
					text = *c.Title + "\n"
				}
				if c.ContentText != nil {
					text += *c.ContentText
				}
				if text == "" {
					continue
				}
				resp, embedErr := genkit.Embed(ctx, g,
					ai.WithEmbedder(noteEmbedder),
					ai.WithTextDocs(text),
					ai.WithConfig(&genai.EmbedContentConfig{
						OutputDimensionality: genai.Ptr[int32](768),
					}),
				)
				if embedErr != nil {
					logger.Error("cron: generating note embedding", "note_id", c.ID, "error", embedErr)
					continue
				}
				if len(resp.Embeddings) == 0 || len(resp.Embeddings[0].Embedding) == 0 {
					continue
				}
				vec := pgvector.NewVector(resp.Embeddings[0].Embedding)
				if storeErr := noteStore.UpdateEmbedding(ctx, c.ID, vec); storeErr != nil {
					logger.Error("cron: storing note embedding", "note_id", c.ID, "error", storeErr)
					continue
				}
				embedded++
			}
			if embedded > 0 {
				logger.Info("cron: note embeddings generated", "count", embedded, "candidates", len(candidates))
			}
		})
	}

	cronScheduler.Start()

	deps := server.Deps{
		Pool: pool,
		Auth: auth.NewHandler(authStore, cfg.JWTSecret, auth.GoogleConfig{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURI:  cfg.GoogleRedirectURI,
			AdminEmail:   cfg.AdminEmail,
			FrontendURL:  cfg.CORSOrigin,
		}, logger),
		Topic:     topic.NewHandler(topicStore, contentStore, topicCache, logger),
		Content:   content.NewHandler(contentStore, cfg.SiteURL, graphCache, feedCache, logger),
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
		Tag:       tag.NewHandler(tagStore, pool, logger),
		NotionSource: func() *notion.SourceHandler {
			sh := notion.NewSourceHandler(notionSourceStore, notionClient, sourceCache, logger)
			sh.SetSyncer(notionHandler)
			return sh
		}(),
		Goal: goal.NewHandler(goalStore, logger),
		Task: task.NewHandler(taskStore, logger,
			task.WithNotion(
				&notionTaskAdapter{client: notionClient},
				&sourceDBResolver{store: notionSourceStore, cache: sourceCache},
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
		Stats:    stats.NewHandler(stats.NewStore(pool), logger),
		Activity: activity.NewHandler(activityStore, logger),
		Session:  session.NewHandler(sessionStore, logger),
		Logger:   logger,
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

// flowObserver adapts server.Metrics to flowrun.FlowObserver.
type flowObserver struct {
	m *server.Metrics
}

func (o *flowObserver) ObserveFlowDuration(flowName, status string, d time.Duration) {
	o.m.FlowDuration.WithLabelValues(flowName, status).Observe(d.Seconds())
}

// notionTaskAdapter adapts notion.Client to task.NotionClient.
type notionTaskAdapter struct {
	client *notion.Client
}

func (a *notionTaskAdapter) UpdatePageStatus(ctx context.Context, pageID, status string) error {
	return a.client.UpdatePageStatus(ctx, pageID, status)
}

func (a *notionTaskAdapter) CreateTaskPage(ctx context.Context, databaseID, title, dueDate, description string) (string, error) {
	return a.client.CreateTask(ctx, notion.CreateTaskParams{
		DatabaseID:  databaseID,
		Title:       title,
		DueDate:     dueDate,
		Description: description,
	})
}

// sourceDBResolver adapts notion.Store + cache to task.DBIDResolver.
type sourceDBResolver struct {
	store *notion.Store
	cache *ristretto.Cache[string, string]
}

func (r *sourceDBResolver) DatabaseIDByRole(ctx context.Context, role string) (string, error) {
	// Check cache first
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
