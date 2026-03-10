package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

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
	"github.com/koopa0/blog-backend/internal/notion"
	"github.com/koopa0/blog-backend/internal/pipeline"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/review"
	"github.com/koopa0/blog-backend/internal/server"
	"github.com/koopa0/blog-backend/internal/topic"
	"github.com/koopa0/blog-backend/internal/tracking"
	"github.com/koopa0/blog-backend/internal/upload"
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
	MockMode            bool
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg := loadConfig(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
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
	feedStore := feed.NewStore(pool)

	// collector + budget
	feedCollector := collector.New(collectedStore, feedStore, logger)
	tokenBudget := budget.New(500_000)

	// upload
	s3Client := upload.NewS3Client(ctx, cfg.R2Endpoint, cfg.R2AccessKeyID, cfg.R2SecretAccessKey)

	// AI pipeline — Genkit + flow registry + runner
	alerter := flowrun.NewLogAlerter(logger)
	var runner *flowrun.Runner
	if cfg.MockMode {
		logger.Info("starting in MOCK MODE — AI calls disabled")
		registry := flow.NewRegistry(
			flow.NewMockContentReview(),
			flow.NewMockContentPolish(),
			flow.NewMockCollectScore(),
			flow.NewMockDigestGenerate(),
			flow.NewMockBookmarkGenerate(),
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

		embedder, embedErr := googleAI.DefineEmbedder(g, "text-embedding-004", &ai.EmbedderOptions{})
		if embedErr != nil {
			return fmt.Errorf("defining embedder: %w", embedErr)
		}

		contentReview := flow.NewContentReview(
			g, geminiModel, embedder,
			contentStore, contentStore, contentStore, reviewStore, topicStore,
			logger,
		)
		contentPolish := flow.NewContentPolish(g, claudeModel, contentStore, logger)
		collectScore := flow.NewCollectScore(g, geminiModel, collectedStore, collectedStore, tokenBudget, logger)
		digestGenerate := flow.NewDigestGenerate(g, geminiModel, contentStore, collectedStore, projectStore, tokenBudget, logger)
		bookmarkGenerate := flow.NewBookmarkGenerate(g, geminiModel, collectedStore, tokenBudget, logger)
		registry := flow.NewRegistry(contentReview, contentPolish, collectScore, digestGenerate, bookmarkGenerate)
		runner = flowrun.New(flowrunStore, registry, 3, alerter, logger)
	}

	runner.Start(ctx)
	defer runner.Stop()

	// cron: retry failed/stuck flow runs every 2 minutes
	cronScheduler := cron.New()
	_, err = cronScheduler.AddFunc("@every 2m", func() {
		runs, retryErr := flowrunStore.RetryableRuns(context.Background())
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
	// cron: collect feeds every 4 hours (hourly_4 schedule)
	_, err = cronScheduler.AddFunc("0 */4 * * *", func() {
		feeds, feedErr := feedStore.EnabledFeedsBySchedule(context.Background(), feed.ScheduleHourly4)
		if feedErr != nil {
			logger.Error("cron: listing hourly_4 feeds", "error", feedErr)
			return
		}
		var totalNew int
		for _, f := range feeds {
			ids, fetchErr := feedCollector.FetchFeed(context.Background(), f)
			if fetchErr != nil {
				logger.Error("cron: collecting feed", "feed_id", f.ID, "error", fetchErr)
				continue
			}
			totalNew += len(ids)
			for _, id := range ids {
				input, _ := json.Marshal(map[string]string{"collected_data_id": id.String()})
				if submitErr := runner.Submit(context.Background(), "collect-and-score", input, nil); submitErr != nil {
					logger.Error("cron: submitting score job", "collected_id", id, "error", submitErr)
				}
			}
		}
		if len(feeds) > 0 {
			logger.Info("cron: hourly_4 collect complete", "feeds", len(feeds), "new_items", totalNew)
		}
	})
	if err != nil {
		return fmt.Errorf("adding hourly_4 cron job: %w", err)
	}

	// cron: collect daily feeds at 06:00
	_, err = cronScheduler.AddFunc("0 6 * * *", func() {
		feeds, feedErr := feedStore.EnabledFeedsBySchedule(context.Background(), feed.ScheduleDaily)
		if feedErr != nil {
			logger.Error("cron: listing daily feeds", "error", feedErr)
			return
		}
		var totalNew int
		for _, f := range feeds {
			ids, fetchErr := feedCollector.FetchFeed(context.Background(), f)
			if fetchErr != nil {
				logger.Error("cron: collecting feed", "feed_id", f.ID, "error", fetchErr)
				continue
			}
			totalNew += len(ids)
			for _, id := range ids {
				input, _ := json.Marshal(map[string]string{"collected_data_id": id.String()})
				if submitErr := runner.Submit(context.Background(), "collect-and-score", input, nil); submitErr != nil {
					logger.Error("cron: submitting score job", "collected_id", id, "error", submitErr)
				}
			}
		}
		if len(feeds) > 0 {
			logger.Info("cron: daily collect complete", "feeds", len(feeds), "new_items", totalNew)
		}
	})
	if err != nil {
		return fmt.Errorf("adding daily cron job: %w", err)
	}

	// cron: collect weekly feeds at 06:00 Monday
	_, err = cronScheduler.AddFunc("0 6 * * 1", func() {
		feeds, feedErr := feedStore.EnabledFeedsBySchedule(context.Background(), feed.ScheduleWeekly)
		if feedErr != nil {
			logger.Error("cron: listing weekly feeds", "error", feedErr)
			return
		}
		var totalNew int
		for _, f := range feeds {
			ids, fetchErr := feedCollector.FetchFeed(context.Background(), f)
			if fetchErr != nil {
				logger.Error("cron: collecting feed", "feed_id", f.ID, "error", fetchErr)
				continue
			}
			totalNew += len(ids)
			for _, id := range ids {
				input, _ := json.Marshal(map[string]string{"collected_data_id": id.String()})
				if submitErr := runner.Submit(context.Background(), "collect-and-score", input, nil); submitErr != nil {
					logger.Error("cron: submitting score job", "collected_id", id, "error", submitErr)
				}
			}
		}
		if len(feeds) > 0 {
			logger.Info("cron: weekly collect complete", "feeds", len(feeds), "new_items", totalNew)
		}
	})
	if err != nil {
		return fmt.Errorf("adding weekly cron job: %w", err)
	}

	// cron: reset token budget at midnight
	_, err = cronScheduler.AddFunc("0 0 * * *", func() {
		tokenBudget.Reset()
		logger.Info("cron: daily token budget reset")
	})
	if err != nil {
		return fmt.Errorf("adding budget reset cron job: %w", err)
	}

	cronScheduler.Start()
	defer cronScheduler.Stop()

	// notion webhook handler
	notionClient := notion.NewClient(cfg.NotionAPIKey)
	notionHandler := notion.NewHandler(notionClient, projectStore, runner, notion.Config{
		APIKey:        cfg.NotionAPIKey,
		WebhookSecret: cfg.NotionWebhookSecret,
		ProjectsDB:    cfg.NotionProjectsDB,
		TasksDB:       cfg.NotionTasksDB,
		BooksDB:       cfg.NotionBooksDB,
	}, logger)

	// pipeline dependencies
	githubFetcher := pipeline.NewGitHub(cfg.GitHubToken, cfg.GitHubRepo)
	topicLookup := pipeline.NewTopicLookup(func(ctx context.Context, slug string) (uuid.UUID, error) {
		t, err := topicStore.TopicBySlug(ctx, slug)
		if err != nil {
			return uuid.UUID{}, err
		}
		return t.ID, nil
	})

	// pipeline handler with collector
	pipelineHandler := pipeline.NewHandler(contentStore, topicLookup, githubFetcher, runner, cfg.GitHubWebhookSecret, logger)
	pipelineHandler.SetCollector(feedCollector, feedStore)

	// flow admin handler
	flowHandler := flow.NewHandler(
		runner,
		&runReaderAdapter{store: flowrunStore},
		contentStore,
		contentStore,
		logger,
	)

	// deps
	deps := server.Deps{
		Auth:      auth.NewHandler(authStore, cfg.JWTSecret, logger),
		Topic:     topic.NewHandler(topicStore, contentStore, logger),
		Content:   content.NewHandler(contentStore, cfg.SiteURL, logger),
		Project:   project.NewHandler(projectStore, logger),
		Review:    review.NewHandler(reviewStore, logger),
		Collected: collected.NewHandler(collectedStore, logger),
		Tracking:  tracking.NewHandler(trackingStore, logger),
		Pipeline:  pipelineHandler,
		FlowRun:   flowrun.NewHandler(flowrunStore, logger),
		Upload:    upload.NewHandler(s3Client, cfg.R2Bucket, cfg.R2PublicURL, logger),
		Flow:      flowHandler,
		Feed:      feed.NewHandler(feedStore, feedCollector, logger),
		Notion:    notionHandler,
		Logger:    logger,
	}

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

	return cfg
}

func runMigrations(databaseURL string, logger *slog.Logger) error {
	m, err := migrate.New("file://migrations", "pgx5://"+databaseURL[len("postgres://"):])
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

// runReaderAdapter bridges flowrun.Store to flow.RunReader,
// converting flowrun.Run to flow.RunResult to avoid an import cycle.
type runReaderAdapter struct {
	store *flowrun.Store
}

func (a *runReaderAdapter) RunResult(ctx context.Context, id uuid.UUID) (*flow.RunResult, error) {
	run, err := a.store.Run(ctx, id)
	if err != nil {
		if errors.Is(err, flowrun.ErrNotFound) {
			return nil, flow.ErrNotFound
		}
		return nil, err
	}
	return toRunResult(run), nil
}

func (a *runReaderAdapter) LatestCompletedRunResult(ctx context.Context, flowName string, contentID uuid.UUID) (*flow.RunResult, error) {
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
