package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/koopa0/koopa-cli/internal/api"
	"github.com/koopa0/koopa-cli/internal/app"
	"github.com/koopa0/koopa-cli/internal/config"
)

// RunServe starts the HTTP API server.
//
// Architecture:
//   - Initializes the application runtime
//   - Creates the HTTP server with all routes
//   - Signal handling is done by caller (executeServe)
func RunServe(ctx context.Context, cfg *config.Config, version, addr string) error {
	logger := slog.Default()
	logger.Info("starting HTTP API server", "version", version)

	// Initialize runtime with all components
	runtime, err := app.NewRuntime(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize runtime: %w", err)
	}
	defer runtime.Cleanup()
	defer func() {
		if err := runtime.Shutdown(); err != nil {
			logger.Warn("failed to shutdown runtime", "error", err)
		}
	}()

	// Create and run HTTP server with the Chat Flow
	server := api.NewServer(runtime.App.DBPool, runtime.App.SessionStore, runtime.Flow, logger)

	logger.Info("HTTP API server ready", "addr", addr)
	return server.Run(ctx, addr)
}
