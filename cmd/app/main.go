// Command app runs the koopa HTTP API server (v2).
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

	"github.com/Koopa0/koopa/internal/activity"
	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/agent/artifact"
	agentnote "github.com/Koopa0/koopa/internal/agent/note"
	agenttask "github.com/Koopa0/koopa/internal/agent/task"
	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/auth"
	"github.com/Koopa0/koopa/internal/bookmark"
	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/db"
	"github.com/Koopa0/koopa/internal/feed"
	"github.com/Koopa0/koopa/internal/feed/collector"
	"github.com/Koopa0/koopa/internal/feed/entry"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/learning/fsrs"
	"github.com/Koopa0/koopa/internal/learning/hypothesis"
	learningplan "github.com/Koopa0/koopa/internal/learning/plan"
	"github.com/Koopa0/koopa/internal/note"
	"github.com/Koopa0/koopa/internal/project"
	"github.com/Koopa0/koopa/internal/search"
	"github.com/Koopa0/koopa/internal/stats"
	"github.com/Koopa0/koopa/internal/systemhealth"
	"github.com/Koopa0/koopa/internal/tag"
	"github.com/Koopa0/koopa/internal/today"
	"github.com/Koopa0/koopa/internal/todo"
	"github.com/Koopa0/koopa/internal/topic"
	"github.com/Koopa0/koopa/internal/upload"
)

// agentSyncTimeout caps how long startup waits for agent.SyncToTable.
// If the DB is too slow or unreachable we fail fast rather than hang
// the app behind a silent reconciliation.
const agentSyncTimeout = 10 * time.Second

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

	// Agent registry — reconcile the Go BuiltinAgents() literal with the
	// agents table before any HTTP traffic. Missing literal entries are
	// retired (status=retired), new ones are inserted as active. Failure
	// here is fatal: an empty or stale agents table means Authorize() cannot
	// resolve callers, so every MCP coordination tool would reject traffic.
	agentRegistry := agent.NewBuiltinRegistry()
	agentStore := agent.NewStore(pool)
	syncCtx, syncCancel := context.WithTimeout(ctx, agentSyncTimeout)
	syncResult, syncErr := agent.SyncToTable(syncCtx, agentRegistry, agentStore, logger)
	syncCancel()
	if syncErr != nil {
		return fmt.Errorf("syncing agent registry: %w", syncErr)
	}
	logger.Info("agent registry synced",
		"active", syncResult.Active,
		"retired", syncResult.Retired,
		"already_retired", syncResult.AlreadyRetired,
	)

	// Stores
	contentStore := content.NewStore(pool)
	bookmarkStore := bookmark.NewStore(pool)
	projectStore := project.NewStore(pool)
	topicStore := topic.NewStore(pool)
	feedStore := feed.NewStore(pool, logger)
	entryStore := entry.NewStore(pool)
	goalStore := goal.NewStore(pool)
	tagStore := tag.NewStore(pool)
	statsStore := stats.NewStore(pool)
	activityStore := activity.NewStore(pool)
	authStore := auth.NewStore(pool)
	hypothesisStore := hypothesis.NewStore(pool)
	todoStore := todo.NewStore(pool)
	artifactStore := artifact.NewStore(pool)
	taskStore := agenttask.NewStore(pool, artifactStore)
	dailyStore := daily.NewStore(pool)
	learningStore := learning.NewStore(pool)
	fsrsStore := fsrs.NewStore(pool)
	noteStore := note.NewStore(pool)
	planStore := learningplan.NewStore(pool)
	agentNoteStore := agentnote.NewStore(pool)

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
		auth:       authHandler,
		content:    content.NewHandler(contentStore, cfg.SiteURL, logger),
		bookmark:   bookmark.NewHandler(bookmarkStore, topicStore, tagStore, logger),
		project:    project.NewHandler(projectStore, todoStore, activityStore, contentStore, logger),
		topic:      topic.NewHandler(topicStore, contentStore, logger),
		feed:       feedHandler,
		entry:      entry.NewHandler(entryStore, logger),
		goal:       goal.NewHandler(goalStore, projectStore, logger),
		tag:        tag.NewHandler(tagStore, logger),
		stats:      stats.NewHandler(statsStore, logger),
		activity:   activity.NewHandler(activityStore, logger),
		upload:     uploadHandler,
		hypothesis: hypothesis.NewHandler(hypothesisStore, logger),
		task:       agenttask.NewHandler(taskStore, artifactStore, agentRegistry, logger),
		agent:      agent.NewHandler(agentRegistry, logger),
		daily:      daily.NewHandler(dailyStore, logger),
		learning:   learning.NewHandler(learningStore, fsrsStore, logger),
		note:       note.NewHandler(noteStore, logger),
		todo:       todo.NewHandler(todoStore, logger),
		plan:       learningplan.NewHandler(planStore, logger),
		fsrs:       fsrs.NewHandler(fsrsStore, logger),
		agentNote:  agentnote.NewHandler(agentNoteStore, logger),
		today:      today.NewHandler(dailyStore, logger),
		search: search.NewHandler([]search.Source{
			content.NewSearchSource(contentStore),
			note.NewSearchSource(noteStore),
		}, logger),
		systemHealth: systemhealth.NewHandler(
			statsFeedHealth{store: statsStore},
			statsProcessRunSuccess{store: statsStore},
			statsContentCount{store: statsStore},
			logger,
		),
		pool:   pool,
		logger: logger,
	}

	authMid := auth.Middleware(cfg.JWTSecret)

	// adminActorMid opens a per-request tx and binds koopa.actor so audit
	// triggers record who mutated each row. Single-admin deployment, so the
	// bound actor is always "human" (see bookmark.curatedByFromContext for
	// the multi-admin upgrade path). adminMid composes authMid outside
	// adminActorMid: JWT validation runs first — failing auth short-circuits
	// before a DB tx is opened.
	adminActorMid := api.ActorMiddleware(pool, "human", logger)
	adminMid := func(next http.Handler) http.Handler {
		return authMid(adminActorMid(next))
	}

	mux := http.NewServeMux()
	registerRoutes(mux, h, authMid, adminMid)

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
