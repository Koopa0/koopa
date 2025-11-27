//go:build wireinject
// +build wireinject

package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/google/wire"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koopa0/koopa-cli/db"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/observability"
	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/sqlc"
	"golang.org/x/sync/errgroup"
)

// InitializeApp is the Wire injector function.
// Wire will automatically generate the implementation of this function.
func InitializeApp(ctx context.Context, cfg *config.Config) (*App, func(), error) {
	wire.Build(
		// Provider Set
		providerSet,
	)
	return nil, nil, nil
}

// OtelShutdown is a cleanup function for OpenTelemetry resources.
// Type alias provides clear semantics for Wire dependency ordering.
type OtelShutdown func()

// providerSet contains all providers.
var providerSet = wire.NewSet(
	// Core providers (order matters for dependencies)
	provideOtelShutdown, // Must be first - sets up tracing before Genkit
	provideGenkit,
	provideEmbedder,
	provideDBPool,
	provideKnowledgeStore, // Returns *knowledge.Store directly (no interface binding needed)
	provideSessionStore,   // Returns *session.Store directly (no interface binding needed)
	providePathValidator,
	provideLogger,                       // Logger for system knowledge indexer
	knowledge.NewSystemKnowledgeIndexer, // System knowledge indexer for CLI commands

	// App constructor
	newApp,
)

// ========== Core Providers ==========

// provideOtelShutdown sets up Datadog tracing before Genkit initialization.
// Must be called before provideGenkit to ensure TracerProvider is ready.
// Returns OtelShutdown (for Wire dependency) and cleanup func (for Wire cleanup chain).
func provideOtelShutdown(ctx context.Context, cfg *config.Config) (OtelShutdown, func(), error) {
	shutdown, err := observability.SetupDatadog(ctx, observability.Config{
		AgentHost:   cfg.Datadog.AgentHost,
		Environment: cfg.Datadog.Environment,
		ServiceName: cfg.Datadog.ServiceName,
	})
	if err != nil {
		return nil, nil, err
	}

	cleanupFn := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdown(shutdownCtx); err != nil {
			slog.Warn("failed to shutdown tracer provider", "error", err)
		}
	}

	// Return OtelShutdown (same as cleanup) for dependency, and cleanup for Wire cleanup chain
	return OtelShutdown(cleanupFn), cleanupFn, nil
}

// provideGenkit initializes Genkit with Google AI plugin and prompt directory.
// Returns error if initialization fails (follows Wire provider pattern).
// Depends on OtelShutdown to ensure tracing is set up first.
func provideGenkit(ctx context.Context, cfg *config.Config, _ OtelShutdown) (*genkit.Genkit, error) {
	// Determine prompt directory from config or use default
	promptDir := cfg.PromptDir
	if promptDir == "" {
		promptDir = "prompts"
	}

	// Initialize Genkit with Google AI plugin and prompt directory
	// This automatically loads all .prompt files from the directory
	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}),
		genkit.WithPromptDir(promptDir),
	)

	// genkit.Init doesn't return error, but we return this signature
	// for consistency with Wire provider pattern and future error handling
	if g == nil {
		return nil, fmt.Errorf("failed to initialize Genkit")
	}

	return g, nil
}

// provideEmbedder creates an embedder instance.
func provideEmbedder(g *genkit.Genkit, cfg *config.Config) ai.Embedder {
	return googlegenai.GoogleAIEmbedder(g, cfg.EmbedderModel)
}

// provideDBPool creates a PostgreSQL connection pool and runs migrations.
// Pool is configured with sensible defaults for connection management.
func provideDBPool(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, func(), error) {
	// Run database migrations on startup (uses URL format)
	if err := db.Migrate(cfg.PostgresURL()); err != nil {
		return nil, nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	// Parse connection string to get config
	poolCfg, err := pgxpool.ParseConfig(cfg.PostgresConnectionString())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse connection config: %w", err)
	}

	// Configure connection pool settings
	poolCfg.MaxConns = 10                      // Maximum number of connections in the pool
	poolCfg.MinConns = 2                       // Minimum number of connections to keep open
	poolCfg.MaxConnLifetime = 30 * time.Minute // Maximum lifetime of a connection
	poolCfg.MaxConnIdleTime = 5 * time.Minute  // Maximum idle time before closing
	poolCfg.HealthCheckPeriod = 1 * time.Minute

	// Create connection pool with config
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Verify connectivity with timeout to fail fast if database is unreachable
	pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
	defer pingCancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("failed to ping database: %w", err)
	}

	cleanup := func() {
		pool.Close()
	}

	return pool, cleanup, nil
}

// provideKnowledgeStore creates a knowledge store instance.
func provideKnowledgeStore(pool *pgxpool.Pool, embedder ai.Embedder) *knowledge.Store {
	return knowledge.New(sqlc.New(pool), embedder, nil)
}

// provideSessionStore creates a session store instance.
// This provides real session persistence using PostgreSQL backend.
func provideSessionStore(pool *pgxpool.Pool) *session.Store {
	return session.New(sqlc.New(pool), pool, nil) // nil = use slog.Default()
}

// providePathValidator creates a path validator instance.
func providePathValidator() (*security.Path, error) {
	// Allow current directory and common paths
	return security.NewPath([]string{"."})
}

// provideLogger creates a logger instance.
// Returns slog.Default() for consistent logging across the application.
func provideLogger() *slog.Logger {
	return slog.Default()
}

// ========== App Constructor ==========

// newApp constructs an App instance.
// Wire automatically injects all dependencies.
// The app.Wait() method should be called during shutdown to wait for all
// background tasks to complete.
func newApp(
	cfg *config.Config,
	ctx context.Context,
	g *genkit.Genkit,
	embedder ai.Embedder,
	pool *pgxpool.Pool,
	knowledgeStore *knowledge.Store,
	sessionStore *session.Store, // Concrete type, not interface
	pathValidator *security.Path,
	systemIndexer *knowledge.SystemKnowledgeIndexer, // System knowledge indexer for CLI commands
) (*App, error) {
	// Create context with cancel
	appCtx, cancel := context.WithCancel(ctx)

	eg, egCtx := errgroup.WithContext(appCtx)

	app := &App{
		Config:        cfg,
		ctx:           appCtx,
		cancel:        cancel,
		eg:            eg,
		egCtx:         egCtx,
		Genkit:        g,
		Embedder:      embedder,
		DBPool:        pool,
		Knowledge:     knowledgeStore,
		SessionStore:  sessionStore, // Concrete type, not interface
		PathValidator: pathValidator,
		SystemIndexer: systemIndexer, // System knowledge indexer for CLI commands
	}

	eg.Go(func() error {
		// Use independent context with timeout (not egCtx) to avoid cancellation
		// during normal shutdown. This is a fire-and-forget operation.
		indexCtx, indexCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer indexCancel()

		count, err := systemIndexer.IndexAll(indexCtx)
		if err != nil {
			// Non-critical error - log and continue (don't fail the errgroup)
			slog.Debug("system knowledge indexing failed (non-critical)", "error", err)
			return nil // Don't propagate error - this is background/optional
		}
		slog.Debug("system knowledge indexed successfully", "count", count)
		return nil
	})

	return app, nil
}
