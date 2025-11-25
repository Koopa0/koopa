package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/koopa0/koopa-cli/internal/app"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/mcp"
	"github.com/koopa0/koopa-cli/internal/tools"
	mcpSdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// RunMCP starts the MCP server on stdio transport
//
// Architecture:
//   - Creates Kit with all tool dependencies
//   - Creates MCP Server wrapping the Kit
//   - Connects to stdio transport for Claude Desktop/Cursor
//   - Signal handling is done by caller (executeMCP)
//
// Error handling:
//   - Returns error if initialization fails (App, Kit, Server)
//   - Returns error if server connection fails
//   - Graceful shutdown on context cancellation
func RunMCP(ctx context.Context, cfg *config.Config, version string) error {
	slog.Info("starting MCP server", "version", version)

	// Initialize application using Wire DI
	application, cleanup, err := app.InitializeApp(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize application: %w", err)
	}
	defer cleanup()
	defer func() {
		if err := application.Close(); err != nil {
			slog.Warn("failed to close application", "error", err)
		}
	}()

	// Create FileToolset with logger
	logger := slog.Default()
	fileToolset, err := tools.NewFileToolset(application.PathValidator, logger)
	if err != nil {
		return fmt.Errorf("failed to create file toolset: %w", err)
	}

	// Create MCP Server with FileToolset
	mcpServer, err := mcp.NewServer(mcp.Config{
		Name:        "koopa",
		Version:     version,
		FileToolset: fileToolset,
	})
	if err != nil {
		return fmt.Errorf("failed to create MCP server: %w", err)
	}

	slog.Info("MCP server initialized", "name", "koopa", "version", version)
	slog.Info("starting MCP server on stdio transport")

	// Run server on stdio transport
	// This is a blocking call that handles all MCP protocol communication
	// The server will run until ctx is cancelled or an error occurs
	if err := mcpServer.Run(ctx, &mcpSdk.StdioTransport{}); err != nil {
		return fmt.Errorf("MCP server error: %w", err)
	}

	slog.Info("MCP server shut down gracefully")
	return nil
}
