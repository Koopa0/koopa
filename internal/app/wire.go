//go:build wireinject
// +build wireinject

package app

import (
	"context"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/google/wire"
	"github.com/jackc/pgx/v5/pgxpool"
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
	provideSessionStore, // Phase 3: Real session persistence
	wire.Bind(new(SessionStore), new(*session.Store)), // Bind concrete to interface for testability
	providePathValidator,

	// App constructor
	newApp,
)

// ========== Core Providers ==========

// provideGenkit initializes Genkit with Google AI plugin.
func provideGenkit(ctx context.Context) *genkit.Genkit {
	return genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}),
		genkit.WithPromptDir("./prompts"),
	)
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

// ========== App Constructor ==========

// newApp constructs an App instance.
// Wire automatically injects all dependencies.
func newApp(
	cfg *config.Config,
	ctx context.Context,
	g *genkit.Genkit,
	embedder ai.Embedder,
	pool *pgxpool.Pool,
	knowledge *knowledge.Store,
	sessionStore SessionStore, // Phase 3: Session persistence (interface for testability)
	pathValidator *security.Path,
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
		Knowledge:     knowledge,
		SessionStore:  sessionStore, // Phase 3: Session persistence (interface for testability)
		PathValidator: pathValidator,
	}

	return app, nil
}
