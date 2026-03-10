package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robfig/cron/v3"

	"github.com/koopa0/blog-backend/internal/auth"
	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/flow"
	"github.com/koopa0/blog-backend/internal/flowrun"
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

	// upload
	s3Client := upload.NewS3Client(ctx, cfg.R2Endpoint, cfg.R2AccessKeyID, cfg.R2SecretAccessKey)

	// AI pipeline — Genkit + flow registry + runner
	var runner *flowrun.Runner
	if cfg.MockMode {
		logger.Info("starting in MOCK MODE — AI calls disabled")
		mockReview := flow.NewMockContentReview()
		registry := flow.NewRegistry(mockReview)
		runner = flowrun.New(flowrunStore, registry, 3, logger)
	} else {
		googleAI := &googlegenai.GoogleAI{}
		g := genkit.Init(ctx, genkit.WithPlugins(googleAI))

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

		contentReview := flow.NewContentReview(
			g, geminiModel,
			contentStore, contentStore, reviewStore, topicStore,
			logger,
		)
		registry := flow.NewRegistry(contentReview)
		runner = flowrun.New(flowrunStore, registry, 3, logger)
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
	cronScheduler.Start()
	defer cronScheduler.Stop()

	// pipeline dependencies
	githubFetcher := pipeline.NewGitHub(cfg.GitHubToken, cfg.GitHubRepo)
	topicLookup := pipeline.NewTopicLookup(func(ctx context.Context, slug string) (uuid.UUID, error) {
		t, err := topicStore.TopicBySlug(ctx, slug)
		if err != nil {
			return uuid.UUID{}, err
		}
		return t.ID, nil
	})

	// deps
	deps := server.Deps{
		Auth:      auth.NewHandler(authStore, cfg.JWTSecret, logger),
		Topic:     topic.NewHandler(topicStore, contentStore, logger),
		Content:   content.NewHandler(contentStore, cfg.SiteURL, logger),
		Project:   project.NewHandler(projectStore, logger),
		Review:    review.NewHandler(reviewStore, logger),
		Collected: collected.NewHandler(collectedStore, logger),
		Tracking:  tracking.NewHandler(trackingStore, logger),
		Pipeline:  pipeline.NewHandler(contentStore, topicLookup, githubFetcher, runner, cfg.GitHubWebhookSecret, logger),
		FlowRun:   flowrun.NewHandler(flowrunStore, logger),
		Upload:    upload.NewHandler(s3Client, cfg.R2Bucket, cfg.R2PublicURL, logger),
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
		CORSOrigin:  envOr("CORS_ORIGIN", "*"),
		SiteURL:     envOr("SITE_URL", "http://localhost:8080"),
		GeminiModel: envOr("GEMINI_MODEL", "gemini-3-flash-preview"),
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
	// googlegenai plugin reads GEMINI_API_KEY (or GOOGLE_API_KEY) from env
	if !cfg.MockMode {
		requireEnv("GEMINI_API_KEY", logger)
	}

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
