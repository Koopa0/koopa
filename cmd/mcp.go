package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/koopa0/koopa/internal/app"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/mcp"
	mcpSdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// runMCP initializes and starts the MCP server on stdio transport.
func runMCP() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	slog.Info("starting MCP server", "version", Version)

	a, err := app.Setup(ctx, cfg)
	if err != nil {
		return fmt.Errorf("initializing application: %w", err)
	}
	defer func() {
		if closeErr := a.Close(); closeErr != nil {
			slog.Warn("shutdown error", "error", closeErr)
		}
	}()

	mcpServer, err := mcp.NewServer(mcp.Config{
		Name:      "koopa",
		Version:   Version,
		Logger:    slog.Default(),
		File:      a.File,
		System:    a.System,
		Network:   a.Network,
		Knowledge: a.Knowledge,
	})
	if err != nil {
		return fmt.Errorf("creating MCP server: %w", err)
	}

	slog.Info("MCP server ready", "name", "koopa", "version", Version, "transport", "stdio")

	if err := mcpServer.Run(ctx, &mcpSdk.StdioTransport{}); err != nil {
		return fmt.Errorf("MCP server error: %w", err)
	}

	slog.Info("MCP server shut down gracefully")
	return nil
}
