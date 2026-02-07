package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/koopa0/koopa/internal/agent/chat"
	"github.com/koopa0/koopa/internal/config"
)

// ChatRuntime provides a fully initialized application runtime with all components ready to use.
// It encapsulates the common initialization logic used by CLI and HTTP server entry points.
// MCP mode uses InitializeApp directly (no chat flow needed).
// Implements io.Closer for resource cleanup.
type ChatRuntime struct {
	App     *App
	Flow    *chat.Flow
	cleanup func() // cleanup (unexported) - handles DB pool, OTel
}

// Close releases all resources. Implements io.Closer.
// Shutdown order: App.Close (goroutines) → cleanup (DB pool, OTel).
func (r *ChatRuntime) Close() error {
	var errs []error

	// 1. App shutdown (cancel context, wait for goroutines)
	if r.App != nil {
		if err := r.App.Close(); err != nil {
			errs = append(errs, fmt.Errorf("app close: %w", err))
		}
	}

	// 2. Cleanup (DB pool, OTel)
	if r.cleanup != nil {
		r.cleanup()
	}

	return errors.Join(errs...)
}

// NewChatRuntime creates a fully initialized runtime with all components ready for use.
// This is the recommended way to initialize Koopa for CLI and HTTP entry points.
//
// Usage:
//
//	runtime, err := app.NewChatRuntime(ctx, cfg)
//	if err != nil { ... }
//	defer runtime.Close()  // Single cleanup method (implements io.Closer)
//	// Use runtime.Flow for agent interactions
func NewChatRuntime(ctx context.Context, cfg *config.Config) (*ChatRuntime, error) {
	// Initialize application
	application, cleanup, err := InitializeApp(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize application: %w", err)
	}

	// Create Chat Agent (uses pre-registered tools)
	chatAgent, err := application.CreateAgent(ctx)
	if err != nil {
		// Must close application first (stops background goroutines)
		// then cleanup (closes DB pool, OTel)
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

	return &ChatRuntime{
		App:     application,
		Flow:    chatFlow,
		cleanup: cleanup,
	}, nil
}
