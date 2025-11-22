//go:build wireinject
// +build wireinject

package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/google/wire"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/koopa0/koopa-cli/internal/session"
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

// providerSet contains all providers.
var providerSet = wire.NewSet(
	// Core providers
	provideGenkit,
	provideEmbedder,
	provideDBPool,
	provideKnowledgeStore,
	wire.Bind(new(agent.KnowledgeStore), new(*knowledge.Store)), // Bind concrete to interface for testability
	provideSessionStore, // Phase 3: Real session persistence
	wire.Bind(new(SessionStore), new(*session.Store)), // Bind concrete to interface for testability
	providePathValidator,
	provideLogger,                       // P2-Phase3: Logger for system indexer
	knowledge.NewSystemKnowledgeIndexer, // P2-Phase3: System knowledge indexer

	// App constructor
	newApp,
)

// ========== Core Providers ==========

// provideGenkit initializes Genkit with Google AI plugin.
// Returns error if initialization fails (follows Wire provider pattern).
func provideGenkit(ctx context.Context) (*genkit.Genkit, error) {
	// For MCP server mode, prompts are not needed, so we make them optional
	// Initialize Genkit without prompts - they're only needed for interactive chat mode
	g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))

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

// provideDBPool creates a PostgreSQL connection pool.
func provideDBPool(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, func(), error) {
	pool, err := pgxpool.New(ctx, cfg.PostgresConnectionString())
	if err != nil {
		return nil, nil, err
	}

	cleanup := func() {
		pool.Close()
	}

	return pool, cleanup, nil
}

// provideKnowledgeStore creates a knowledge store instance.
func provideKnowledgeStore(pool *pgxpool.Pool, embedder ai.Embedder) *knowledge.Store {
	return knowledge.New(pool, embedder, nil)
}

// provideSessionStore creates a session store instance.
// This provides real session persistence using PostgreSQL backend.
func provideSessionStore(pool *pgxpool.Pool) *session.Store {
	return session.New(pool, nil) // nil = use slog.Default()
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
func newApp(
	cfg *config.Config,
	ctx context.Context,
	g *genkit.Genkit,
	embedder ai.Embedder,
	pool *pgxpool.Pool,
	knowledgeStore *knowledge.Store,
	sessionStore SessionStore, // Phase 3: Session persistence (interface for testability)
	pathValidator *security.Path,
	systemIndexer *knowledge.SystemKnowledgeIndexer, // P2-Phase3: System knowledge indexer
) (*App, error) {
	// Create context with cancel
	appCtx, cancel := context.WithCancel(ctx)

	app := &App{
		Config:        cfg,
		ctx:           appCtx,
		cancel:        cancel,
		Genkit:        g,
		Embedder:      embedder,
		DBPool:        pool,
		Knowledge:     knowledgeStore,
		SessionStore:  sessionStore, // Phase 3: Session persistence (interface for testability)
		PathValidator: pathValidator,
		SystemIndexer: systemIndexer, // P2-Phase3: System knowledge indexer
	}

	// P2-Phase3: Index system knowledge on startup (async, non-blocking)
	go func() {
		// Use app context for proper lifecycle management
		indexCtx, indexCancel := context.WithTimeout(appCtx, 5*time.Second)
		defer indexCancel()

		count, err := systemIndexer.IndexAll(indexCtx)
		if err != nil {
			slog.Warn("system knowledge indexing failed (non-critical)", "error", err)
		} else {
			slog.Info("system knowledge indexed successfully", "count", count)
		}
	}()

	return app, nil
}
