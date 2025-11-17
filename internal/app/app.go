// Package app provides application initialization and dependency injection.
//
// App is the core container that orchestrates all application components using Wire for DI.
// It initializes Genkit, database connection, knowledge store,
// and creates the agent with all necessary dependencies.
package app

import (
	"context"
	"log/slog"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/koopa0/koopa-cli/internal/session"
)

// SessionStore defines the interface for session persistence operations.
// This interface is consumed by both the agent package and cmd package.
// Following Go best practices: interfaces are defined by the consumer.
type SessionStore interface {
	// Agent methods
	CreateSession(ctx context.Context, title, modelName, systemPrompt string) (*session.Session, error)
	GetSession(ctx context.Context, sessionID uuid.UUID) (*session.Session, error)
	GetMessages(ctx context.Context, sessionID uuid.UUID, limit, offset int) ([]*session.Message, error)
	AddMessages(ctx context.Context, sessionID uuid.UUID, messages []*session.Message) error

	// CLI command methods
	ListSessions(ctx context.Context, limit, offset int) ([]*session.Session, error)
	DeleteSession(ctx context.Context, sessionID uuid.UUID) error
}

// App is the core application container.
type App struct {
	// Configuration
	Config *config.Config

	// Core services
	Genkit        *genkit.Genkit
	Embedder      ai.Embedder // Explicitly exported for Wire
	DBPool        *pgxpool.Pool
	Knowledge     *knowledge.Store
	SessionStore  SessionStore // Phase 3: Session persistence (interface for testability)
	PathValidator *security.Path

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
}

// Close gracefully shuts down all resources.
func (a *App) Close() error {
	slog.Info("shutting down application")

	// 1. Cancel context
	if a.cancel != nil {
		a.cancel()
	}

	// 2. Close database pool
	if a.DBPool != nil {
		a.DBPool.Close()
		slog.Info("database pool closed")
	}

	return nil
}

// CreateAgent creates an Agent for a specific use case.
// Session persistence is now fully wired via Wire DI (P1-Phase3 complete).
func (a *App) CreateAgent(ctx context.Context, retriever ai.Retriever) (*agent.Agent, error) {
	return agent.New(ctx, a.Config, a.Genkit, retriever, a.SessionStore, slog.Default())
}
