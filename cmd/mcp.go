package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/koopa0/koopa/internal/app"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/mcp"
	"github.com/koopa0/koopa/internal/security"
	"github.com/koopa0/koopa/internal/tools"
	mcpSdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// runMCP initializes and starts the MCP server.
// This is called when the user runs `koopa mcp`.
func runMCP() error {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return RunMCP(ctx, cfg, Version)
}

// RunMCP starts the MCP server on stdio transport
//
// Architecture:
//   - Creates all toolsets with necessary dependencies
//   - Creates MCP Server wrapping the toolsets
//   - Connects to stdio transport for Claude Desktop/Cursor
//   - Signal handling is done by caller (executeMCP)
//
// Error handling:
//   - Returns error if initialization fails (App, Toolsets, Server)
//   - Returns error if server connection fails
//   - Graceful shutdown on context cancellation
func RunMCP(ctx context.Context, cfg *config.Config, version string) error {
	slog.Info("starting MCP server", "version", version)

	// Initialize application
	application, cleanup, err := app.InitializeApp(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize application: %w", err)
	}
	// Cleanup order: App.Close (goroutines) first, then cleanup (DB pool, OTel)
	defer cleanup()
	defer func() {
		if closeErr := application.Close(); closeErr != nil {
			slog.Warn("app close error", "error", closeErr)
		}
	}()

	// Create all required tools with logger
	logger := slog.Default()

	// 1. FileTools
	fileTools, err := tools.NewFileTools(application.PathValidator, logger)
	if err != nil {
		return fmt.Errorf("failed to create file tools: %w", err)
	}

	// 2. SystemTools
	cmdValidator := security.NewCommand()
	envValidator := security.NewEnv()
	systemTools, err := tools.NewSystemTools(cmdValidator, envValidator, logger)
	if err != nil {
		return fmt.Errorf("failed to create system tools: %w", err)
	}

	// 3. NetworkTools
	networkTools, err := tools.NewNetworkTools(tools.NetworkConfig{
		SearchBaseURL:    cfg.SearXNG.BaseURL,
		FetchParallelism: cfg.WebScraper.Parallelism,
		FetchDelay:       time.Duration(cfg.WebScraper.DelayMs) * time.Millisecond,
		FetchTimeout:     time.Duration(cfg.WebScraper.TimeoutMs) * time.Millisecond,
	}, logger)
	if err != nil {
		return fmt.Errorf("failed to create network tools: %w", err)
	}

	// 4. KnowledgeTools (optional - requires retriever from App)
	var knowledgeTools *tools.KnowledgeTools
	toolCategories := []string{"file", "system", "network"}
	if application.Retriever != nil {
		kt, ktErr := tools.NewKnowledgeTools(application.Retriever, application.DocStore, logger)
		if ktErr != nil {
			slog.Warn("knowledge tools unavailable", "error", ktErr)
		} else {
			knowledgeTools = kt
			toolCategories = append(toolCategories, "knowledge")
		}
	}

	// Create MCP Server with all tools
	mcpServer, err := mcp.NewServer(mcp.Config{
		Name:           "koopa",
		Version:        version,
		FileTools:      fileTools,
		SystemTools:    systemTools,
		NetworkTools:   networkTools,
		KnowledgeTools: knowledgeTools,
	})
	if err != nil {
		return fmt.Errorf("failed to create MCP server: %w", err)
	}

	slog.Info("MCP server initialized",
		"name", "koopa",
		"version", version,
		"tools", toolCategories)
	slog.Info("starting MCP server on stdio transport")

	// Run server on stdio transport
	// This is a blocking call that handles all MCP protocol communication
	// The server will run until ctx is canceled or an error occurs
	if err := mcpServer.Run(ctx, &mcpSdk.StdioTransport{}); err != nil {
		return fmt.Errorf("MCP server error: %w", err)
	}

	slog.Info("MCP server shut down gracefully")
	return nil
}
