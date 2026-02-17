// Package app provides application initialization and lifecycle management.
//
// App is the core container that holds all application components.
// Created by Setup, released by Close.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/postgresql"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/koopa/internal/chat"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/memory"
	"github.com/koopa0/koopa/internal/security"
	"github.com/koopa0/koopa/internal/session"
	"github.com/koopa0/koopa/internal/tools"
)

// App is the application instance.
// Created by Setup, closed by Close. All entry points (CLI, HTTP, MCP)
// use this struct to access shared resources.
type App struct {
	Config        *config.Config
	Genkit        *genkit.Genkit
	Embedder      ai.Embedder
	DBPool        *pgxpool.Pool
	DocStore      *postgresql.DocStore
	Retriever     ai.Retriever
	SessionStore  *session.Store
	MemoryStore   *memory.Store
	PathValidator *security.Path
	Tools         []ai.Tool // Pre-registered Genkit tools (for chat agent)

	// Concrete toolsets shared by CLI and MCP entry points.
	File      *tools.File
	System    *tools.System
	Network   *tools.Network
	Knowledge *tools.Knowledge // nil if retriever unavailable

	// Lifecycle management (unexported except bgCtx for agent construction)
	bgCtx       context.Context // Outlives individual requests; canceled by Close().
	cancel      func()
	wg          sync.WaitGroup // tracks background goroutines (scheduler, memory extraction)
	dbCleanup   func()
	otelCleanup func()
	closeOnce   sync.Once
}

// Close gracefully shuts down all resources. Safe for concurrent and
// repeated calls — cleanup runs exactly once via sync.Once.
//
// Shutdown order:
//  1. Cancel context (signals background tasks to stop)
//  2. Wait for background goroutines (scheduler) to exit
//  3. Close DB pool
//  4. Flush OTel spans
func (a *App) Close() error {
	a.closeOnce.Do(func() {
		slog.Info("shutting down application")

		// 1. Cancel context (signals all background tasks to stop)
		if a.cancel != nil {
			a.cancel()
		}

		// 2. Wait for background goroutines to finish
		a.wg.Wait()

		// 3. Close DB pool
		if a.dbCleanup != nil {
			a.dbCleanup()
		}

		// 4. Flush OTel spans
		if a.otelCleanup != nil {
			a.otelCleanup()
		}
	})
	return nil
}

// CreateAgent creates a Chat Agent using pre-registered tools.
// Tools are registered once at Setup (not lazily).
// Setup guarantees all dependencies are non-nil.
func (a *App) CreateAgent() (*chat.Agent, error) {
	agent, err := chat.New(chat.Config{
		Genkit:        a.Genkit,
		SessionStore:  a.SessionStore,
		MemoryStore:   a.MemoryStore,
		Logger:        slog.Default(),
		Tools:         a.Tools,
		ModelName:     a.Config.FullModelName(),
		MaxTurns:      a.Config.MaxTurns,
		Language:      a.Config.Language,
		BackgroundCtx: a.bgCtx,
		WG:            &a.wg,
	})
	if err != nil {
		return nil, fmt.Errorf("creating chat agent: %w", err)
	}
	return agent, nil
}
