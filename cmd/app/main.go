// Command app runs the koopa0.dev HTTP API server (v2).
//
// This serves the Angular frontend. MCP tools are in cmd/mcp.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa0.dev/internal/activity"
	"github.com/Koopa0/koopa0.dev/internal/admin"
	"github.com/Koopa0/koopa0.dev/internal/auth"
	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/db"
	"github.com/Koopa0/koopa0.dev/internal/feed"
	"github.com/Koopa0/koopa0.dev/internal/feed/collector"
	"github.com/Koopa0/koopa0.dev/internal/feed/entry"
	"github.com/Koopa0/koopa0.dev/internal/goal"
	"github.com/Koopa0/koopa0.dev/internal/note"
	"github.com/Koopa0/koopa0.dev/internal/project"
	"github.com/Koopa0/koopa0.dev/internal/stats"
	"github.com/Koopa0/koopa0.dev/internal/tag"
	"github.com/Koopa0/koopa0.dev/internal/topic"
	"github.com/Koopa0/koopa0.dev/internal/upload"
)

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

	if err := runMigrations(cfg.DatabaseURL, logger); err != nil {
		return err
	}

	pool, err := connectDB(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	logger.Info("database connected")

	// Stores
	contentStore := content.NewStore(pool)
	projectStore := project.NewStore(pool)
	topicStore := topic.NewStore(pool)
	feedStore := feed.NewStore(pool, logger)
	entryStore := entry.NewStore(pool)
	goalStore := goal.NewStore(pool)
	tagStore := tag.NewStore(pool)
	statsStore := stats.NewStore(pool)
	activityStore := activity.NewStore(pool)
	authStore := auth.NewStore(pool)
	noteStore := note.NewStore(pool)

	// Feed collector for manual fetch + scheduled fetch
	feedCollector := collector.New(entryStore, feedStore, logger)
	defer feedCollector.Stop()

	// Feed scheduler — background goroutine for periodic feed fetching
	var wg sync.WaitGroup
	feedScheduler := feed.NewScheduler(feedStore, feedCollector, db.New(pool), logger)
	wg.Go(func() { feedScheduler.Run(ctx) })

	// Upload (optional — only if R2 is configured)
	var uploadHandler *upload.Handler
	if cfg.R2Endpoint != "" {
		s3Client := upload.NewS3Client(ctx, cfg.R2Endpoint, cfg.R2AccessKeyID, cfg.R2SecretAccessKey)
		uploadHandler = upload.NewHandler(s3Client, cfg.R2Bucket, cfg.R2PublicURL, logger)
	}

	// Auth (optional — only if Google OAuth is configured)
	var authHandler *auth.Handler
	if cfg.GoogleClientID != "" {
		authHandler = auth.NewHandler(authStore, cfg.JWTSecret, &auth.GoogleConfig{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURI:  cfg.GoogleRedirectURI,
			AdminEmail:   cfg.AdminEmail,
			FrontendURL:  cfg.CORSOrigin,
		}, logger)
	}

	// Feed handler (optional — collector needed)
	var feedHandler *feed.Handler
	if feedCollector != nil {
		feedHandler = feed.NewHandler(feedStore, feedCollector, logger)
	}

	h := &handlers{
		auth:     authHandler,
		content:  content.NewHandler(contentStore, cfg.SiteURL, logger),
		project:  project.NewHandler(projectStore, logger),
		topic:    topic.NewHandler(topicStore, contentStore, logger),
		feed:     feedHandler,
		entry:    entry.NewHandler(entryStore, logger),
		goal:     goal.NewHandler(goalStore, logger),
		tag:      tag.NewHandler(tagStore, logger),
		stats:    stats.NewHandler(statsStore, logger),
		activity: activity.NewHandler(activityStore, logger),
		upload:   uploadHandler,
		note:     note.NewHandler(noteStore, logger),
		adminV2:  admin.NewHandler(pool, nil, logger),
		pool:     pool,
		logger:   logger,
	}

	authMid := auth.Middleware(cfg.JWTSecret)

	mux := http.NewServeMux()
	registerRoutes(mux, h, authMid)

	handler := chain(mux,
		recovery(logger),
		requestID,
		cors(cfg.CORSOrigin),
		logging(logger),
		securityHeaders,
	)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("server starting", "port", cfg.Port)
		if sErr := srv.ListenAndServe(); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
			errCh <- sErr
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}
	wg.Wait()
	logger.Info("server stopped")
	return nil
}

func connectDB(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing DATABASE_URL: %w", err)
	}
	poolCfg.MaxConns = 10
	poolCfg.MinConns = 2
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	if pingErr := pool.Ping(ctx); pingErr != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", pingErr)
	}
	return pool, nil
}

func runMigrations(databaseURL string, logger *slog.Logger) error {
	m, err := migrate.New("file://migrations", "pgx5://"+databaseURL[len("postgres://"):])
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("running migrations: %w", err)
	}
	srcErr, dbErr := m.Close()
	if srcErr != nil {
		return fmt.Errorf("closing migration source: %w", srcErr)
	}
	if dbErr != nil {
		return fmt.Errorf("closing migration db: %w", dbErr)
	}
	logger.Info("migrations applied")
	return nil
}
