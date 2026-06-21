// Copyright 2026 Koopa. All rights reserved.

// Command app runs the koopa HTTP API server — the public and admin
// JSON API consumed by the Angular frontend, plus the background feed
// collection and embedding reconciliation loops. MCP tools are served
// separately by cmd/mcp.
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

	"github.com/exaring/otelpgx"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"go.opentelemetry.io/otel/metric"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/activity"
	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/auth"
	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/db"
	"github.com/Koopa0/koopa/internal/embedder"
	"github.com/Koopa0/koopa/internal/feed"
	"github.com/Koopa0/koopa/internal/feed/collector"
	"github.com/Koopa0/koopa/internal/feed/entry"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/note"
	"github.com/Koopa0/koopa/internal/project"
	"github.com/Koopa0/koopa/internal/reading"
	"github.com/Koopa0/koopa/internal/search"
	"github.com/Koopa0/koopa/internal/song"
	"github.com/Koopa0/koopa/internal/stats"
	"github.com/Koopa0/koopa/internal/tag"
	"github.com/Koopa0/koopa/internal/today"
	"github.com/Koopa0/koopa/internal/todo"
	"github.com/Koopa0/koopa/internal/topic"
)

// agentSyncTimeout caps how long startup waits for agent.SyncToTable.
// If the DB is too slow or unreachable we fail fast rather than hang
// the app behind a silent reconciliation.
const agentSyncTimeout = 10 * time.Second

// embedReconcileInterval is how often the embedding reconciler rescans
// contents and notes for rows with NULL embeddings. New rows are embedded
// within roughly one interval of landing.
const embedReconcileInterval = 60 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) == 2 && os.Args[1] == "embed-backfill" {
		if err := runBackfill(logger); err != nil {
			logger.Error("embed-backfill failed", "error", err)
			os.Exit(1)
		}
		return
	}
	if err := run(logger); err != nil {
		logger.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

// runBackfill is the embed-backfill one-shot: drain every contents/notes
// row missing an embedding, log the counts, and exit without serving
// HTTP. The exit status reflects success — rows that failed to embed
// surface as an error so a partially-drained run is visible to the
// operator. Schema migrations are not run; the backfill targets a
// database the serving binary already migrated.
func runBackfill(logger *slog.Logger) error {
	cfg := loadBackfillConfig(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	pool, err := connectDB(ctx, cfg.DatabaseURL, nil)
	if err != nil {
		return err
	}
	defer pool.Close()

	emb, err := embedder.New(ctx, cfg.GeminiAPIKey)
	if err != nil {
		return fmt.Errorf("initializing gemini embedder: %w", err)
	}
	reconciler := embedder.NewReconciler(emb, content.NewStore(pool), note.NewStore(pool), logger)

	res, err := reconciler.RunOnce(ctx)
	if err != nil {
		return fmt.Errorf("embed backfill: %w", err)
	}
	logger.Info("embed backfill complete",
		"contents", res.Contents, "notes", res.Notes, "failed", res.Failed)
	if res.Failed > 0 {
		return fmt.Errorf("embed backfill: %d rows failed to embed", res.Failed)
	}
	return nil
}

// run wires every subsystem and starts the HTTP server. Its cyclomatic
// complexity exceeds the project cap because wiring inherently fans out
// (each subsystem brings its own error-check + optional-config branch),
// but every branch is linear — no nested conditions, no early-return
// shortcuts that interact. Splitting further would scatter the wiring
// order across helpers without making the failure modes easier to read.
//
//nolint:gocyclo // wiring func; branches are linear init + error guards
func run(logger *slog.Logger) error {
	cfg := loadConfig(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	meterProvider, metricsHandler, observabilityShutdown, err := setupObservability(ctx, observabilityConfig{
		Enabled:        cfg.ObservabilityEnabled,
		ServiceName:    "koopa-app",
		ServiceVersion: cfg.ServiceVersion,
		Environment:    cfg.Environment,
	}, logger)
	if err != nil {
		return fmt.Errorf("setting up observability: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := observabilityShutdown(shutdownCtx); shutdownErr != nil {
			logger.Warn("observability shutdown failed", "error", shutdownErr)
		}
	}()

	if err := runMigrations(cfg.DatabaseURL, logger); err != nil {
		return err
	}

	pool, err := setupPool(ctx, cfg.DatabaseURL, cfg.queryTracingOn(), meterProvider, logger)
	if err != nil {
		return err
	}
	defer pool.Close()
	logger.Info("database connected")

	// Agent registry — reconcile the Go BuiltinAgents() literal with the
	// agents table before any HTTP traffic. Missing literal entries are
	// retired (status=retired), new ones are inserted as active. Failure
	// here is fatal: an empty or stale agents table means the caller-identity
	// gates cannot resolve callers, so every gated MCP tool would reject
	// traffic and audit-row FKs to agents.name would not resolve.
	agentRegistry := agent.NewBuiltinRegistry()
	agentStore := agent.NewStore(pool)
	syncCtx, syncCancel := context.WithTimeout(ctx, agentSyncTimeout)
	syncResult, syncErr := agent.SyncToTable(syncCtx, agentRegistry, agentStore, meterProvider, logger)
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
	projectStore := project.NewStore(pool)
	topicStore := topic.NewStore(pool)
	feedStore := feed.NewStore(pool, logger)
	entryStore := entry.NewStore(pool)
	goalStore := goal.NewStore(pool)
	tagStore := tag.NewStore(pool)
	statsStore := stats.NewStore(pool)
	activityStore := activity.NewStore(pool)
	authStore := auth.NewStore(pool)
	todoStore := todo.NewStore(pool)
	dailyStore := daily.NewStore(pool)
	noteStore := note.NewStore(pool)
	readingStore := reading.NewStore(pool)
	songStore := song.NewStore(pool)

	// Feed collector for manual fetch + scheduled fetch
	feedCollector := collector.New(entryStore, feedStore, logger)
	defer feedCollector.Stop()

	// Feed scheduler — background goroutine for periodic feed fetching
	var wg sync.WaitGroup
	if err := startFeedScheduler(ctx, &wg, feedSchedulerDeps{
		Feeds:    feedStore,
		Fetcher:  feedCollector,
		Recorder: db.New(pool),
		MP:       meterProvider,
		Logger:   logger,
	}); err != nil {
		return err
	}

	// Embedding reconciler (optional — only if Gemini is configured).
	// Runs entirely outside the request path: the Gemini call must never
	// sit inside a handler's per-request tx or latency budget. Shares the
	// scheduler WaitGroup so shutdown waits for an in-flight pass to
	// observe ctx cancellation.
	if cfg.GeminiAPIKey != "" {
		emb, embErr := embedder.New(ctx, cfg.GeminiAPIKey)
		if embErr != nil {
			return fmt.Errorf("initializing gemini embedder: %w", embErr)
		}
		reconciler := embedder.NewReconciler(emb, contentStore, noteStore, logger)
		wg.Go(func() { reconciler.Run(ctx, embedReconcileInterval) })
		logger.Info("embedding reconciler started", "interval", embedReconcileInterval.String())
	} else {
		logger.Info("embedding reconciler disabled, search stays FTS-only (GEMINI_API_KEY unset)")
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
		project:    project.NewHandler(projectStore, todoStore, activityStore, contentStore, logger),
		topic:      topic.NewHandler(topicStore, contentStore, logger),
		feed:       feedHandler,
		entry:      entry.NewHandler(entryStore, logger),
		goal:       goal.NewHandler(goalStore, projectStore, logger),
		tag:        tag.NewHandler(tagStore, logger),
		stats:      stats.NewHandler(statsStore, logger),
		activity:   activity.NewHandler(activityStore, logger),
		agent:      agent.NewHandler(agentRegistry, logger),
		daily:      daily.NewHandler(dailyStore, todoStore, logger),
		note:       note.NewHandler(noteStore, logger),
		reading:    reading.NewHandler(readingStore, logger),
		song:       song.NewHandler(songStore, logger),
		todo:       todo.NewHandler(todoStore, logger),
		// Today is the HTTP mirror of brief(mode=morning): the same domain
		// stores feed both. The contracted readers — todo date views, the
		// day's committed plan, active goals, and RSS highlights — are wired
		// to the real stores below.
		today: today.NewHandler(dailyStore, logger).WithSources(
			todoStore,
			goalStore,
			entryStore,
		),
		search: search.NewHandler([]search.Source{
			content.NewSearchSource(contentStore),
			note.NewSearchSource(noteStore),
		}, logger),
		pool:           pool,
		logger:         logger,
		metricsHandler: metricsHandler,
	}

	authMid := auth.Middleware(cfg.JWTSecret)

	// adminActorMid opens a per-request tx and binds koopa.actor so audit
	// triggers record who mutated each row. Single-admin deployment, so the
	// bound actor is always "human"; a multi-admin upgrade would resolve the
	// actor from the authenticated identity instead. adminMid composes authMid
	// outside adminActorMid: JWT validation runs first — failing auth
	// short-circuits before a DB tx is opened.
	adminActorMid := api.ActorMiddleware(pool, "human", logger)
	adminMid := func(next http.Handler) http.Handler {
		return authMid(adminActorMid(next))
	}

	mux := http.NewServeMux()
	registerRoutes(mux, h, authMid, adminMid)

	// Wrap mux INSIDE the outer middleware chain: httpMetrics's deferred
	// observation reads r.Pattern, which ServeMux populates in place
	// before invoking the matched handler (Go 1.22+). Sitting outside the
	// recovery middleware would mean panics skip our metric; sitting at
	// this position means recovery still catches the panic AFTER our
	// defer fires. See cmd/app/middleware.go::httpMetrics.
	metricsMW, err := httpMetrics(meterProvider.Meter("koopa-app"))
	if err != nil {
		return fmt.Errorf("creating http metrics middleware: %w", err)
	}
	instrumentedMux := metricsMW(mux)

	handler := chain(instrumentedMux,
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
		MaxHeaderBytes:    1 << 20, // 1 MB — bound request header size (security.md)
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

// connectDB opens the pgxpool. When tracer is non-nil, it is set on the
// pool's ConnConfig so otelpgx can record per-query spans + metrics. The
// caller decides whether observability is enabled; connectDB just wires
// the tracer it is handed.
func connectDB(ctx context.Context, databaseURL string, tracer pgx.QueryTracer) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing DATABASE_URL: %w", err)
	}
	poolCfg.MaxConns = 10
	poolCfg.MinConns = 2
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = 30 * time.Second
	if tracer != nil {
		poolCfg.ConnConfig.Tracer = tracer
	}

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

// feedSchedulerDeps bundles the wiring dependencies for
// startFeedScheduler so the helper stays at ≤5 parameters per
// .claude/rules/go-philosophy.md.
type feedSchedulerDeps struct {
	Feeds    *feed.Store
	Fetcher  feed.ManualFetcher
	Recorder feed.CrawlRunRecorder
	MP       metric.MeterProvider
	Logger   *slog.Logger
}

// startFeedScheduler constructs the feed scheduler with its observability
// instruments and launches its run loop on the provided WaitGroup.
// Failure to construct is fatal — broken instrument wiring is a startup
// bug, not a runtime condition.
func startFeedScheduler(ctx context.Context, wg *sync.WaitGroup, deps feedSchedulerDeps) error {
	scheduler, err := feed.NewScheduler(deps.Feeds, deps.Fetcher, deps.Recorder, deps.MP, deps.Logger)
	if err != nil {
		return fmt.Errorf("creating feed scheduler: %w", err)
	}
	wg.Go(func() { scheduler.Run(ctx) })
	return nil
}

// setupPool opens the pgxpool with an optional otelpgx tracer and, when
// enabled, registers the pool-stats collector. The single boolean folds
// the all-or-nothing kill-switch check (Q3): the caller decides whether
// observability + query tracing are both on. Pool-stats registration
// failure is logged but not fatal — stats are nice-to-have, not a
// startup invariant.
func setupPool(ctx context.Context, dbURL string, queryTracingOn bool, mp metric.MeterProvider, logger *slog.Logger) (*pgxpool.Pool, error) {
	var tracer pgx.QueryTracer
	if queryTracingOn {
		tracer = otelpgx.NewTracer(
			otelpgx.WithMeterProvider(mp),
			otelpgx.WithTrimSQLInSpanName(),
		)
	}
	pool, err := connectDB(ctx, dbURL, tracer)
	if err != nil {
		return nil, err
	}
	if queryTracingOn {
		if statsErr := otelpgx.RecordStats(pool, otelpgx.WithStatsMeterProvider(mp)); statsErr != nil {
			logger.Warn("otelpgx pool stats registration failed", "error", statsErr)
		}
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
