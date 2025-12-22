package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/koopa0/koopa/internal/agent/chat"
	"github.com/koopa0/koopa/internal/config"
)

// Runtime provides a fully initialized application runtime with all components ready to use.
// It encapsulates the common initialization logic used by CLI, HTTP server, and other entry points.
// Implements io.Closer for resource cleanup.
type Runtime struct {
	App     *App
	Flow    *chat.Flow
	cleanup func() // Wire cleanup (unexported) - handles DB pool, OTel
}

// Close releases all resources. Implements io.Closer.
// Shutdown order: App.Close (goroutines) → Wire cleanup (DB pool, OTel).
func (r *Runtime) Close() error {
	var errs []error

	// 1. App shutdown (cancel context, wait for goroutines)
	if r.App != nil {
		if err := r.App.Close(); err != nil {
			errs = append(errs, fmt.Errorf("app close: %w", err))
		}
	}

	// 2. Wire cleanup (DB pool, OTel)
	if r.cleanup != nil {
		r.cleanup()
	}

	return errors.Join(errs...)
}

// NewRuntime creates a fully initialized runtime with all components ready for use.
// This is the recommended way to initialize Koopa for any entry point (CLI, HTTP, etc.).
//
// Usage:
//
//	runtime, err := app.NewRuntime(ctx, cfg)
//	if err != nil { ... }
//	defer runtime.Close()  // Single cleanup method (implements io.Closer)
//	// Use runtime.Flow for agent interactions
func NewRuntime(ctx context.Context, cfg *config.Config) (*Runtime, error) {
	// Initialize application using Wire DI
	application, cleanup, err := InitializeApp(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize application: %w", err)
	}

	// Create Chat Agent (uses pre-registered tools from Wire DI)
	chatAgent, err := application.CreateAgent(ctx)
	if err != nil {
		// Must close application first (stops background goroutines)
		// then Wire cleanup (closes DB pool, OTel)
		if closeErr := application.Close(); closeErr != nil {
			slog.Warn("app close failed during CreateAgent recovery", "error", closeErr)
		}
		cleanup()
		return nil, fmt.Errorf("failed to create agent: %w", err)
	}

	// Initialize Chat Flow (singleton pattern with explicit lifecycle)
	chatFlow, err := chat.InitFlow(application.Genkit, chatAgent)
	if err != nil {
		// InitFlow failed (likely called twice) - cleanup and return error
		if closeErr := application.Close(); closeErr != nil {
			slog.Warn("app close failed during InitFlow recovery", "error", closeErr)
		}
		cleanup()
		return nil, fmt.Errorf("failed to init flow: %w", err)
	}

	return &Runtime{
		App:     application,
		Flow:    chatFlow,
		cleanup: cleanup,
	}, nil
}
