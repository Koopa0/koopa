//go:build wireinject
// +build wireinject

package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/firebase/genkit/go/plugins/postgresql"
	"github.com/google/wire"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/koopa/db"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/observability"
	"github.com/koopa0/koopa/internal/rag"
	"github.com/koopa0/koopa/internal/security"
	"github.com/koopa0/koopa/internal/session"
	"github.com/koopa0/koopa/internal/sqlc"
	"github.com/koopa0/koopa/internal/tools"
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
	provideDBPool,
	providePostgresPlugin, // PostgresEngine + Postgres plugin
	provideGenkit,         // Genkit with PostgreSQL plugin
	provideEmbedder,       // Embedder for DocStore
	provideRAGComponents,  // Genkit PostgreSQL DocStore + Retriever
	wire.FieldsOf(new(*RAGComponents), "DocStore", "Retriever"), // Extract fields for DI
	provideSessionStore,  // Returns *session.Store directly (no interface binding needed)
	providePathValidator, // Path validator for security
	provideTools,         // Register all tools at construction time (Rob Pike: "initialization belongs in constructors")

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

// providePostgresPlugin creates the Genkit PostgreSQL plugin.
// This wraps our existing connection pool for use with Genkit's DocStore.
func providePostgresPlugin(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config) (*postgresql.Postgres, error) {
	// Create PostgresEngine with existing connection pool
	// WithDatabase is required even when using WithPool
	pEngine, err := postgresql.NewPostgresEngine(ctx,
		postgresql.WithPool(pool),
		postgresql.WithDatabase(cfg.PostgresDBName),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create postgres engine: %w", err)
	}

	// Return Postgres plugin struct
	return &postgresql.Postgres{Engine: pEngine}, nil
}

// provideGenkit initializes Genkit with Google AI and PostgreSQL plugins.
// Returns error if initialization fails (follows Wire provider pattern).
// Depends on OtelShutdown to ensure tracing is set up first.
func provideGenkit(ctx context.Context, cfg *config.Config, _ OtelShutdown, postgres *postgresql.Postgres) (*genkit.Genkit, error) {
	// Determine prompt directory from config or use default
	promptDir := cfg.PromptDir
	if promptDir == "" {
		promptDir = "prompts"
	}

	// Initialize Genkit with Google AI and PostgreSQL plugins
	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}, postgres),
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

// RAGComponents holds DocStore and Retriever created together by Genkit.
// Wire doesn't support returning multiple values, so we use a struct.
type RAGComponents struct {
	DocStore  *postgresql.DocStore
	Retriever ai.Retriever
}

// provideRAGComponents creates Genkit PostgreSQL DocStore and Retriever.
// DocStore is used for indexing documents, Retriever for searching.
func provideRAGComponents(ctx context.Context, g *genkit.Genkit, postgres *postgresql.Postgres, embedder ai.Embedder) (*RAGComponents, error) {
	cfg := rag.NewDocStoreConfig(embedder)
	docStore, retriever, err := postgresql.DefineRetriever(ctx, g, postgres, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to define retriever: %w", err)
	}

	return &RAGComponents{
		DocStore:  docStore,
		Retriever: retriever,
	}, nil
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

// provideTools registers all tools at construction time.
// This follows Rob Pike's principle: "Initialization belongs in constructors."
// Tools are registered once here, not lazily in CreateAgent.
func provideTools(g *genkit.Genkit, pathValidator *security.Path, retriever ai.Retriever, cfg *config.Config) ([]ai.Tool, error) {
	logger := slog.Default()
	var allTools []ai.Tool

	// 1. File tools
	ft, err := tools.NewFileTools(pathValidator, logger)
	if err != nil {
		return nil, fmt.Errorf("creating file tools: %w", err)
	}
	fileTools, err := tools.RegisterFileTools(g, ft)
	if err != nil {
		return nil, fmt.Errorf("registering file tools: %w", err)
	}
	allTools = append(allTools, fileTools...)

	// 2. System tools
	cmdValidator := security.NewCommand()
	envValidator := security.NewEnv()
	st, err := tools.NewSystemTools(cmdValidator, envValidator, logger)
	if err != nil {
		return nil, fmt.Errorf("creating system tools: %w", err)
	}
	systemTools, err := tools.RegisterSystemTools(g, st)
	if err != nil {
		return nil, fmt.Errorf("registering system tools: %w", err)
	}
	allTools = append(allTools, systemTools...)

	// 3. Network tools
	nt, err := tools.NewNetworkTools(tools.NetworkConfig{
		SearchBaseURL:    cfg.SearXNG.BaseURL,
		FetchParallelism: cfg.WebScraper.Parallelism,
		FetchDelay:       time.Duration(cfg.WebScraper.DelayMs) * time.Millisecond,
		FetchTimeout:     time.Duration(cfg.WebScraper.TimeoutMs) * time.Millisecond,
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("creating network tools: %w", err)
	}
	networkTools, err := tools.RegisterNetworkTools(g, nt)
	if err != nil {
		return nil, fmt.Errorf("registering network tools: %w", err)
	}
	allTools = append(allTools, networkTools...)

	// 4. Knowledge tools (uses Genkit Retriever)
	kt, err := tools.NewKnowledgeTools(retriever, logger)
	if err != nil {
		return nil, fmt.Errorf("creating knowledge tools: %w", err)
	}
	knowledgeTools, err := tools.RegisterKnowledgeTools(g, kt)
	if err != nil {
		return nil, fmt.Errorf("registering knowledge tools: %w", err)
	}
	allTools = append(allTools, knowledgeTools...)

	slog.Info("tools registered at construction", "count", len(allTools))
	return allTools, nil
}

// ========== App Constructor ==========

// newApp constructs an App instance.
// Wire automatically injects all dependencies.
// Tools are pre-registered by provideTools (Rob Pike: "initialization in constructors").
func newApp(
	cfg *config.Config,
	ctx context.Context,
	g *genkit.Genkit,
	embedder ai.Embedder,
	pool *pgxpool.Pool,
	docStore *postgresql.DocStore,
	retriever ai.Retriever,
	sessionStore *session.Store,
	pathValidator *security.Path,
	tools []ai.Tool,
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
		DocStore:      docStore,
		Retriever:     retriever,
		SessionStore:  sessionStore,
		PathValidator: pathValidator,
		Tools:         tools, // Pre-registered by provideTools
	}

	// Index system knowledge in background (fire-and-forget)
	eg.Go(func() error {
		// Use independent context with timeout (not egCtx) to avoid cancellation
		// during normal shutdown. This is a fire-and-forget operation.
		indexCtx, indexCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer indexCancel()

		count, err := rag.IndexSystemKnowledge(indexCtx, docStore, pool)
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
