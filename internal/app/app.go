// Package app provides application initialization and dependency injection.
//
// App is the core container that orchestrates all application components with struct-based DI.
// It initializes Genkit, database connection, DocStore (via Genkit PostgreSQL Plugin),
// and creates the agent with all necessary dependencies.
package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/postgresql"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koopa0/koopa/internal/agent/chat"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/security"
	"github.com/koopa0/koopa/internal/session"
	"golang.org/x/sync/errgroup"
)

// App is the core application container.
type App struct {
	// Configuration
	Config *config.Config

	Genkit        *genkit.Genkit
	Embedder      ai.Embedder
	DBPool        *pgxpool.Pool        // Database connection pool
	DocStore      *postgresql.DocStore // Genkit PostgreSQL DocStore for indexing
	Retriever     ai.Retriever         // Genkit Retriever for searching
	SessionStore  *session.Store       // Session persistence (concrete type, not interface)
	PathValidator *security.Path       // Path validator for security
	Tools         []ai.Tool            // Pre-registered tools

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc

	// errgroup for background goroutine lifecycle management
	eg *errgroup.Group
}

// Close gracefully shuts down App-managed resources.
// Cleanup function handles DB pool and OTel (single owner principle).
//
// Shutdown order:
// 1. Cancel context (signals background tasks to stop)
// 2. Wait for background goroutines (errgroup)
func (a *App) Close() error {
	slog.Info("shutting down application")

	// 1. Cancel context (signals all background tasks to stop)
	if a.cancel != nil {
		a.cancel()
	}

	// 2. Wait for background goroutines
	if a.eg != nil {
		if err := a.eg.Wait(); err != nil {
			return fmt.Errorf("background task error: %w", err)
		}
		slog.Debug("background tasks completed")
	}

	// Pool is closed by cleanup function, NOT here (single owner principle)
	return nil
}

// Wait blocks until all background goroutines complete.
// This is useful for waiting on background tasks without closing resources.
func (a *App) Wait() error {
	if a.eg == nil {
		return nil
	}
	if err := a.eg.Wait(); err != nil {
		return fmt.Errorf("errgroup failed: %w", err)
	}
	return nil
}

// Go starts a new background goroutine tracked by the app's errgroup.
// Use this for any background tasks that should be waited on during shutdown.
func (a *App) Go(f func() error) {
	if a.eg != nil {
		a.eg.Go(f)
	}
}

// CreateAgent creates a Chat Agent using pre-registered tools.
// Tools are registered once at App construction (not lazily).
// InitializeApp guarantees all dependencies are non-nil.
func (a *App) CreateAgent(_ context.Context) (*chat.Chat, error) {
	// No nil checks - InitializeApp guarantees injection
	return chat.New(chat.Config{
		Genkit:       a.Genkit,
		Retriever:    a.Retriever,
		SessionStore: a.SessionStore,
		Logger:       slog.Default(),
		Tools:        a.Tools,
		ModelName:    a.Config.FullModelName(),
		MaxTurns:     a.Config.MaxTurns,
		RAGTopK:      a.Config.RAGTopK,
		Language:     a.Config.Language,
	})
}
