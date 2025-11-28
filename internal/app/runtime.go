package app

import (
	"context"
	"fmt"

	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/rag"
)

// Runtime provides a fully initialized application runtime with all components ready to use.
// It encapsulates the common initialization logic used by CLI, HTTP server, and other entry points.
type Runtime struct {
	App      *App
	Flow     *chat.Flow
	Cleanup  func()
	Shutdown func() error
}

// NewRuntime creates a fully initialized runtime with all components ready for use.
// This is the recommended way to initialize Koopa for any entry point (CLI, HTTP, etc.).
//
// Usage:
//
//	runtime, err := app.NewRuntime(ctx, cfg)
//	if err != nil { ... }
//	defer runtime.Cleanup()
//	defer runtime.Shutdown()
//	// Use runtime.Flow for agent interactions
func NewRuntime(ctx context.Context, cfg *config.Config) (*Runtime, error) {
	// Initialize application using Wire DI
	application, cleanup, err := InitializeApp(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize application: %w", err)
	}

	// Create RAG retriever
	retriever := rag.New(application.Knowledge)
	_ = retriever.DefineDocument(application.Genkit, "documents")

	// Create Chat Agent
	chatAgent, err := application.CreateAgent(ctx, retriever)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to create agent: %w", err)
	}

	// Get or define Chat Flow (singleton pattern)
	chatFlow := chat.GetFlow(application.Genkit, chatAgent)

	return &Runtime{
		App:      application,
		Flow:     chatFlow,
		Cleanup:  cleanup,
		Shutdown: application.Close,
	}, nil
}
