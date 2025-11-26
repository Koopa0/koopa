package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/koopa0/koopa-cli/api"
	"github.com/koopa0/koopa-cli/internal/app"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/rag"
)

// RunServe starts the HTTP API server.
//
// Architecture:
//   - Initializes the application using Wire DI
//   - Creates the HTTP server with all routes
//   - Signal handling is done by caller (executeServe)
func RunServe(ctx context.Context, cfg *config.Config, version string, addr string) error {
	logger := slog.Default()
	logger.Info("starting HTTP API server", "version", version)

	// Initialize application using Wire DI
	application, cleanup, err := app.InitializeApp(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize application: %w", err)
	}
	defer cleanup()
	defer func() {
		if err := application.Close(); err != nil {
			logger.Warn("failed to close application", "error", err)
		}
	}()

	// Create retriever for documents
	ret := rag.New(application.Knowledge)
	_ = ret.DefineDocument(application.Genkit, "documents")

	// Create Chat Agent
	chatAgent, err := application.CreateAgent(ctx, ret)
	if err != nil {
		return fmt.Errorf("error creating agent: %w", err)
	}

	// Define Flow for the agent and get the Flow for API exposure
	chatFlow := chatAgent.DefineFlow(application.Genkit)

	// Create and run HTTP server with the Chat Flow
	server := api.NewServer(application.DBPool, application.SessionStore, chatFlow, logger)

	logger.Info("HTTP API server ready", "addr", addr)
	return server.Run(ctx, addr)
}
