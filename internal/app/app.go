// Package app provides application initialization and dependency injection.
//
// App is the core container that orchestrates all application components using Wire for DI.
// It initializes Genkit, database connection, knowledge store,
// and creates the agent with all necessary dependencies.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/rag"
	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/tools"
	"golang.org/x/sync/errgroup"
)

// App is the core application container.
type App struct {
	// Configuration
	Config *config.Config

	// Core services
	Genkit        *genkit.Genkit
	Embedder      ai.Embedder // Explicitly exported for Wire
	DBPool        *pgxpool.Pool
	Knowledge     *knowledge.Store
	SessionStore  *session.Store // Session persistence (concrete type, not interface)
	PathValidator *security.Path
	SystemIndexer *knowledge.SystemKnowledgeIndexer // System knowledge indexer for CLI commands

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc

	// errgroup for background goroutine lifecycle management
	eg    *errgroup.Group
	egCtx context.Context
}

// Close gracefully shuts down all resources.
//
// Shutdown order:
// 1. Cancel context (signals background tasks to stop)
// 2. Wait for background goroutines (errgroup)
// 3. Close database pool
func (a *App) Close() error {
	slog.Info("shutting down application")

	// 1. Cancel context (signals all background tasks to stop)
	if a.cancel != nil {
		a.cancel()
	}

	if a.eg != nil {
		if err := a.eg.Wait(); err != nil {
			slog.Warn("background task error during shutdown", "error", err)
		}
		slog.Debug("background tasks completed")
	}

	// 3. Close database pool (after all background tasks are done)
	if a.DBPool != nil {
		a.DBPool.Close()
		slog.Info("database pool closed")
	}

	return nil
}

// Wait blocks until all background goroutines complete.
// This is useful for waiting on background tasks without closing resources.
func (a *App) Wait() error {
	if a.eg == nil {
		return nil
	}
	return a.eg.Wait()
}

// Go starts a new background goroutine tracked by the app's errgroup.
// Use this for any background tasks that should be waited on during shutdown.
func (a *App) Go(f func() error) {
	if a.eg != nil {
		a.eg.Go(f)
	}
}

// CreateAgent creates a Chat Agent for a specific use case.
// Session persistence is fully wired via Wire DI.
// Knowledge store support includes conversation history and document search.
func (a *App) CreateAgent(ctx context.Context, retriever *rag.Retriever) (*chat.Chat, error) {
	// Defensive: Validate required dependencies
	if a.Config == nil {
		return nil, fmt.Errorf("CreateAgent: Config is nil - App not properly initialized")
	}
	if a.Genkit == nil {
		return nil, fmt.Errorf("CreateAgent: Genkit is nil - App not properly initialized")
	}
	if a.SessionStore == nil {
		return nil, fmt.Errorf("CreateAgent: SessionStore is nil - App not properly initialized")
	}
	if a.Knowledge == nil {
		return nil, fmt.Errorf("CreateAgent: Knowledge store is nil - App not properly initialized")
	}
	if retriever == nil {
		return nil, fmt.Errorf("CreateAgent: retriever parameter is nil")
	}

	// Create all Toolsets with logging support for debugging
	logger := slog.Default()

	// 1. FileToolset
	fileToolset, err := tools.NewFileToolset(a.PathValidator, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create file toolset: %w", err)
	}

	// 2. SystemToolset
	cmdValidator := security.NewCommand()
	envValidator := security.NewEnv()
	systemToolset, err := tools.NewSystemToolset(cmdValidator, envValidator, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create system toolset: %w", err)
	}

	// 3. NetworkToolset (web search + fetch)
	networkToolset, err := tools.NewNetworkToolset(
		a.Config.SearXNG.BaseURL,
		a.Config.WebScraper.Parallelism,
		time.Duration(a.Config.WebScraper.DelayMs)*time.Millisecond,
		time.Duration(a.Config.WebScraper.TimeoutMs)*time.Millisecond,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create network toolset: %w", err)
	}

	// 4. KnowledgeToolset
	knowledgeToolset, err := tools.NewKnowledgeToolset(a.Knowledge, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create knowledge toolset: %w", err)
	}

	// Create Chat Agent with required dependencies
	chatAgent, err := chat.New(chat.Deps{
		Config:         a.Config,
		Genkit:         a.Genkit,
		Retriever:      retriever,
		SessionStore:   a.SessionStore,
		KnowledgeStore: a.Knowledge,
		Logger:         logger,
		Toolsets:       []tools.Toolset{fileToolset, systemToolset, networkToolset, knowledgeToolset},
	})
	if err != nil {
		return nil, fmt.Errorf("CreateAgent: chat.New failed: %w", err)
	}

	return chatAgent, nil
}
