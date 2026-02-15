package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core/api"
	"github.com/firebase/genkit/go/core/tracing"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/compat_oai/openai"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/firebase/genkit/go/plugins/ollama"
	"github.com/firebase/genkit/go/plugins/postgresql"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/koopa0/koopa/db"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/rag"
	"github.com/koopa0/koopa/internal/security"
	"github.com/koopa0/koopa/internal/session"
	"github.com/koopa0/koopa/internal/sqlc"
	"github.com/koopa0/koopa/internal/tools"
)

// Setup creates and initializes the application.
// Returns an App with embedded cleanup — call Close() to release.
func Setup(ctx context.Context, cfg *config.Config) (_ *App, retErr error) {
	a := &App{Config: cfg}

	// On error, clean up everything already initialized
	defer func() {
		if retErr != nil {
			if err := a.Close(); err != nil {
				slog.Warn("cleanup during setup failure", "error", err)
			}
		}
	}()

	a.otelCleanup = provideOtelShutdown(ctx, cfg)

	pool, dbCleanup, err := provideDBPool(ctx, cfg)
	if err != nil {
		return nil, err
	}
	a.dbCleanup = dbCleanup
	a.DBPool = pool

	postgres, err := providePostgresPlugin(ctx, pool, cfg)
	if err != nil {
		return nil, err
	}

	g, err := provideGenkit(ctx, cfg, postgres)
	if err != nil {
		return nil, err
	}
	a.Genkit = g

	embedder := provideEmbedder(g, cfg)
	if embedder == nil {
		return nil, fmt.Errorf("embedder %q not found for provider %q", cfg.EmbedderModel, cfg.Provider)
	}
	a.Embedder = embedder

	docStore, retriever, err := provideRAGComponents(ctx, g, postgres, embedder)
	if err != nil {
		return nil, err
	}
	a.DocStore = docStore
	a.Retriever = retriever

	a.SessionStore = provideSessionStore(pool)

	path, err := providePathValidator()
	if err != nil {
		return nil, err
	}
	a.PathValidator = path

	if err := provideTools(a); err != nil {
		return nil, err
	}

	// Set up lifecycle management
	_, cancel := context.WithCancel(ctx)
	a.cancel = cancel

	return a, nil
}

// provideOtelShutdown sets up Datadog tracing before Genkit initialization.
// Must be called before provideGenkit to ensure TracerProvider is ready.
//
// Traces are exported to a local Datadog Agent via OTLP HTTP (localhost:4318).
// The Agent handles authentication, buffering, and forwarding to Datadog backend.
func provideOtelShutdown(ctx context.Context, cfg *config.Config) func() {
	dd := cfg.Datadog

	agentHost := dd.AgentHost
	if agentHost == "" {
		agentHost = "localhost:4318"
	}

	// Set OTEL env vars for Genkit's TracerProvider to pick up.
	// SAFETY: os.Setenv is not concurrent-safe, but this function is called
	// exactly once during startup in Setup, before goroutines are spawned.
	if dd.ServiceName != "" {
		_ = os.Setenv("OTEL_SERVICE_NAME", dd.ServiceName)
	}
	if dd.Environment != "" {
		_ = os.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment="+dd.Environment)
	}

	// Create OTLP HTTP exporter pointing to local Datadog Agent.
	// Agent handles authentication and forwarding to Datadog backend.
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(agentHost),
		otlptracehttp.WithInsecure(), // localhost doesn't need TLS
	)
	if err != nil {
		slog.Warn("creating datadog exporter, tracing disabled", "error", err)
		return func() {}
	}

	// Register BatchSpanProcessor with Genkit's TracerProvider.
	processor := sdktrace.NewBatchSpanProcessor(exporter)
	tracing.TracerProvider().RegisterSpanProcessor(processor)

	slog.Debug("datadog tracing enabled",
		"agent", agentHost,
		"service", dd.ServiceName,
		"environment", dd.Environment,
	)

	shutdown := tracing.TracerProvider().Shutdown

	//nolint:contextcheck // Independent context: shutdown runs during teardown when parent is canceled
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdown(shutdownCtx); err != nil {
			slog.Warn("shutting down tracer provider", "error", err)
		}
	}
}

// providePostgresPlugin creates the Genkit PostgreSQL plugin.
// This wraps our existing connection pool for use with Genkit's DocStore.
func providePostgresPlugin(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config) (*postgresql.Postgres, error) {
	pEngine, err := postgresql.NewPostgresEngine(ctx, postgresql.WithPool(pool), postgresql.WithDatabase(cfg.PostgresDBName))
	if err != nil {
		return nil, fmt.Errorf("creating postgres engine: %w", err)
	}

	return &postgresql.Postgres{Engine: pEngine}, nil
}

// provideGenkit initializes Genkit with the configured AI provider and PostgreSQL plugins.
// Supports gemini (default), ollama, and openai providers.
// Call ordering in Setup ensures tracing is set up first.
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
			return nil, errors.New("initializing genkit with ollama provider")
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
			return nil, errors.New("initializing genkit with openai provider")
		}
		slog.Info("initialized Genkit with openai provider", "model", cfg.ModelName)

	default: // "gemini"
		g = genkit.Init(ctx,
			genkit.WithPlugins(&googlegenai.GoogleAI{}, postgres),
			genkit.WithPromptDir(promptDir),
		)
		if g == nil {
			return nil, errors.New("initializing genkit with gemini provider")
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
		return nil, nil, fmt.Errorf("running migrations: %w", err)
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.PostgresConnectionString())
	if err != nil {
		return nil, nil, fmt.Errorf("parsing connection config: %w", err)
	}

	poolCfg.MaxConns = 10
	poolCfg.MinConns = 2
	poolCfg.MaxConnLifetime = 30 * time.Minute
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = 1 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("creating connection pool: %w", err)
	}

	pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
	defer pingCancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("pinging database: %w", err)
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
		return nil, nil, fmt.Errorf("defining retriever: %w", err)
	}

	return docStore, retriever, nil
}

// provideSessionStore creates a session store instance.
func provideSessionStore(pool *pgxpool.Pool) *session.Store {
	return session.New(sqlc.New(pool), pool, nil)
}

// providePathValidator creates a path validator instance.
// Denies access to prompts/ to protect system prompt files from tool-based access.
func providePathValidator() (*security.Path, error) {
	return security.NewPath([]string{"."}, []string{"prompts"})
}

// provideTools creates toolsets, registers them with Genkit, and stores both
// the concrete toolsets and the Genkit-wrapped references in a.
func provideTools(a *App) error {
	logger := slog.Default()
	cfg := a.Config
	var allTools []ai.Tool

	ft, err := tools.NewFile(a.PathValidator, logger)
	if err != nil {
		return fmt.Errorf("creating file tools: %w", err)
	}
	a.File = ft
	fileTools, err := tools.RegisterFile(a.Genkit, ft)
	if err != nil {
		return fmt.Errorf("registering file tools: %w", err)
	}
	allTools = append(allTools, fileTools...)

	cmdValidator := security.NewCommand()
	envValidator := security.NewEnv()
	st, err := tools.NewSystem(cmdValidator, envValidator, logger)
	if err != nil {
		return fmt.Errorf("creating system tools: %w", err)
	}
	a.System = st
	systemTools, err := tools.RegisterSystem(a.Genkit, st)
	if err != nil {
		return fmt.Errorf("registering system tools: %w", err)
	}
	allTools = append(allTools, systemTools...)

	nt, err := tools.NewNetwork(tools.NetConfig{
		SearchBaseURL:    cfg.SearXNG.BaseURL,
		FetchParallelism: cfg.WebScraper.Parallelism,
		FetchDelay:       time.Duration(cfg.WebScraper.DelayMs) * time.Millisecond,
		FetchTimeout:     time.Duration(cfg.WebScraper.TimeoutMs) * time.Millisecond,
	}, logger)
	if err != nil {
		return fmt.Errorf("creating network tools: %w", err)
	}
	a.Network = nt
	networkTools, err := tools.RegisterNetwork(a.Genkit, nt)
	if err != nil {
		return fmt.Errorf("registering network tools: %w", err)
	}
	allTools = append(allTools, networkTools...)

	kt, err := tools.NewKnowledge(a.Retriever, a.DocStore, logger)
	if err != nil {
		return fmt.Errorf("creating knowledge tools: %w", err)
	}
	a.Knowledge = kt
	knowledgeTools, err := tools.RegisterKnowledge(a.Genkit, kt)
	if err != nil {
		return fmt.Errorf("registering knowledge tools: %w", err)
	}
	allTools = append(allTools, knowledgeTools...)

	a.Tools = allTools
	slog.Info("tools registered at construction", "count", len(allTools))
	return nil
}
