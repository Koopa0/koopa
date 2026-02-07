package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core/api"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/compat_oai/openai"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/firebase/genkit/go/plugins/ollama"
	"github.com/firebase/genkit/go/plugins/postgresql"
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

// InitializeApp creates and initializes all application dependencies.
// Returns the App, a cleanup function for infrastructure resources (DB pool, OTel),
// and any initialization error.
func InitializeApp(ctx context.Context, cfg *config.Config) (*App, func(), error) {
	otelCleanup, err := provideOtelShutdown(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	pool, dbCleanup, err := provideDBPool(ctx, cfg)
	if err != nil {
		otelCleanup()
		return nil, nil, err
	}
	postgres, err := providePostgresPlugin(ctx, pool, cfg)
	if err != nil {
		dbCleanup()
		otelCleanup()
		return nil, nil, err
	}
	g, err := provideGenkit(ctx, cfg, postgres)
	if err != nil {
		dbCleanup()
		otelCleanup()
		return nil, nil, err
	}
	embedder := provideEmbedder(g, cfg)
	docStore, retriever, err := provideRAGComponents(ctx, g, postgres, embedder)
	if err != nil {
		dbCleanup()
		otelCleanup()
		return nil, nil, err
	}
	store := provideSessionStore(pool)
	path, err := providePathValidator()
	if err != nil {
		dbCleanup()
		otelCleanup()
		return nil, nil, err
	}
	v, err := provideTools(g, path, retriever, docStore, cfg)
	if err != nil {
		dbCleanup()
		otelCleanup()
		return nil, nil, err
	}
	application := newApp(ctx, cfg, g, embedder, pool, docStore, retriever, store, path, v)

	// Start background system knowledge indexing.
	// Launched here (not in newApp) to keep the constructor side-effect free.
	//nolint:contextcheck // Independent context: indexing must complete even if parent is canceled
	application.Go(func() error {
		indexCtx, indexCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer indexCancel()

		count, err := rag.IndexSystemKnowledge(indexCtx, docStore, pool)
		if err != nil {
			slog.Debug("system knowledge indexing failed (non-critical)", "error", err)
			return nil
		}
		slog.Debug("system knowledge indexed successfully", "count", count)
		return nil
	})

	return application, func() {
		dbCleanup()
		otelCleanup()
	}, nil
}

// provideOtelShutdown sets up Datadog tracing before Genkit initialization.
// Must be called before provideGenkit to ensure TracerProvider is ready.
func provideOtelShutdown(ctx context.Context, cfg *config.Config) (func(), error) {
	shutdown, err := observability.SetupDatadog(ctx, observability.Config{
		AgentHost:   cfg.Datadog.AgentHost,
		Environment: cfg.Datadog.Environment,
		ServiceName: cfg.Datadog.ServiceName,
	})
	if err != nil {
		return nil, err
	}

	//nolint:contextcheck // Independent context: shutdown runs during teardown when parent is canceled
	cleanupFn := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdown(shutdownCtx); err != nil {
			slog.Warn("failed to shutdown tracer provider", "error", err)
		}
	}
	return cleanupFn, nil
}

// providePostgresPlugin creates the Genkit PostgreSQL plugin.
// This wraps our existing connection pool for use with Genkit's DocStore.
func providePostgresPlugin(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config) (*postgresql.Postgres, error) {
	pEngine, err := postgresql.NewPostgresEngine(ctx, postgresql.WithPool(pool), postgresql.WithDatabase(cfg.PostgresDBName))
	if err != nil {
		return nil, fmt.Errorf("failed to create postgres engine: %w", err)
	}

	return &postgresql.Postgres{Engine: pEngine}, nil
}

// provideGenkit initializes Genkit with the configured AI provider and PostgreSQL plugins.
// Supports gemini (default), ollama, and openai providers.
// Call ordering in InitializeApp ensures tracing is set up first.
func provideGenkit(ctx context.Context, cfg *config.Config, postgres *postgresql.Postgres) (*genkit.Genkit, error) {
	promptDir := cfg.PromptDir
	if promptDir == "" {
		promptDir = "prompts"
	}

	provider := cfg.Provider
	if provider == "" {
		provider = "gemini"
	}

	var g *genkit.Genkit

	switch provider {
	case "ollama":
		ollamaPlugin := &ollama.Ollama{ServerAddress: cfg.OllamaHost}
		g = genkit.Init(ctx,
			genkit.WithPlugins(ollamaPlugin, postgres),
			genkit.WithPromptDir(promptDir),
		)
		if g == nil {
			return nil, fmt.Errorf("failed to initialize Genkit with ollama provider")
		}
		// Ollama requires explicit model registration (no auto-discovery)
		ollamaPlugin.DefineModel(g, ollama.ModelDefinition{
			Name: cfg.ModelName,
			Type: "chat",
		}, nil)
		// Register embedder for RAG
		ollamaPlugin.DefineEmbedder(g, cfg.OllamaHost, cfg.EmbedderModel, nil)
		slog.Info("initialized Genkit with ollama provider",
			"model", cfg.ModelName, "host", cfg.OllamaHost)

	case "openai":
		g = genkit.Init(ctx,
			genkit.WithPlugins(&openai.OpenAI{}, postgres),
			genkit.WithPromptDir(promptDir),
		)
		if g == nil {
			return nil, fmt.Errorf("failed to initialize Genkit with openai provider")
		}
		slog.Info("initialized Genkit with openai provider", "model", cfg.ModelName)

	default: // "gemini"
		g = genkit.Init(ctx,
			genkit.WithPlugins(&googlegenai.GoogleAI{}, postgres),
			genkit.WithPromptDir(promptDir),
		)
		if g == nil {
			return nil, fmt.Errorf("failed to initialize Genkit with gemini provider")
		}
		slog.Info("initialized Genkit with gemini provider", "model", cfg.ModelName)
	}

	return g, nil
}

// provideEmbedder looks up the embedder registered by the AI provider plugin.
// Each provider registers embedders differently:
//   - gemini: GoogleAIEmbedder(g, modelName)
//   - ollama: registered in provideGenkit, keyed by server address
//   - openai: auto-registered in Init(), looked up by model name
func provideEmbedder(g *genkit.Genkit, cfg *config.Config) ai.Embedder {
	provider := cfg.Provider
	if provider == "" {
		provider = "gemini"
	}

	switch provider {
	case "ollama":
		// Ollama embedder is keyed by server address (registered in provideGenkit)
		return ollama.Embedder(g, cfg.OllamaHost)
	case "openai":
		// OpenAI auto-registers embedders in Init()
		return genkit.LookupEmbedder(g, api.NewName("openai", cfg.EmbedderModel))
	default: // "gemini"
		return googlegenai.GoogleAIEmbedder(g, cfg.EmbedderModel)
	}
}

// provideDBPool creates a PostgreSQL connection pool and runs migrations.
// Pool is configured with sensible defaults for connection management.
func provideDBPool(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, func(), error) {
	if err := db.Migrate(cfg.PostgresURL()); err != nil {
		return nil, nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.PostgresConnectionString())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse connection config: %w", err)
	}

	poolCfg.MaxConns = 10
	poolCfg.MinConns = 2
	poolCfg.MaxConnLifetime = 30 * time.Minute
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = 1 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

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

// provideRAGComponents creates Genkit PostgreSQL DocStore and Retriever.
// DocStore is used for indexing documents, Retriever for searching.
func provideRAGComponents(ctx context.Context, g *genkit.Genkit, postgres *postgresql.Postgres, embedder ai.Embedder) (*postgresql.DocStore, ai.Retriever, error) {
	cfg := rag.NewDocStoreConfig(embedder)
	docStore, retriever, err := postgresql.DefineRetriever(ctx, g, postgres, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to define retriever: %w", err)
	}

	return docStore, retriever, nil
}

// provideSessionStore creates a session store instance.
func provideSessionStore(pool *pgxpool.Pool) *session.Store {
	return session.New(sqlc.New(pool), pool, nil)
}

// providePathValidator creates a path validator instance.
func providePathValidator() (*security.Path, error) {
	return security.NewPath([]string{"."})
}

// provideTools registers all tools at construction time.
// Tools are registered once here, not lazily in CreateAgent.
func provideTools(g *genkit.Genkit, pathValidator *security.Path, retriever ai.Retriever, docStore *postgresql.DocStore, cfg *config.Config) ([]ai.Tool, error) {
	logger := slog.Default()
	var allTools []ai.Tool

	ft, err := tools.NewFileTools(pathValidator, logger)
	if err != nil {
		return nil, fmt.Errorf("creating file tools: %w", err)
	}
	fileTools, err := tools.RegisterFileTools(g, ft)
	if err != nil {
		return nil, fmt.Errorf("registering file tools: %w", err)
	}
	allTools = append(allTools, fileTools...)

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

	kt, err := tools.NewKnowledgeTools(retriever, docStore, logger)
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

// newApp constructs an App instance with all dependencies.
// All dependencies are injected by InitializeApp.
// Tools are pre-registered by provideTools.
// NOTE: This constructor has no side effects. Background tasks are started by the caller.
func newApp(
	ctx context.Context,
	cfg *config.Config,
	g *genkit.Genkit,
	embedder ai.Embedder,
	pool *pgxpool.Pool,
	docStore *postgresql.DocStore,
	retriever ai.Retriever,
	sessionStore *session.Store,
	pathValidator *security.Path, registeredTools []ai.Tool,
) *App {

	appCtx, cancel := context.WithCancel(ctx)

	eg, _ := errgroup.WithContext(appCtx)

	app := &App{
		Config:        cfg,
		ctx:           appCtx,
		cancel:        cancel,
		eg:            eg,
		Genkit:        g,
		Embedder:      embedder,
		DBPool:        pool,
		DocStore:      docStore,
		Retriever:     retriever,
		SessionStore:  sessionStore,
		PathValidator: pathValidator,
		Tools:         registeredTools,
	}

	return app
}
