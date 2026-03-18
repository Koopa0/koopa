// Command mcp runs a Model Context Protocol server over stdio, exposing
// read-only tools for querying obsidian notes, projects, and activity events.
//
// Usage:
//
//	DATABASE_URL=postgres://... go run ./cmd/mcp
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/blog-backend/internal/activity"
	mcpserver "github.com/koopa0/blog-backend/internal/mcp"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/project"
)

func main() {
	// MCP stdio protocol uses stdout — log to stderr only.
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		logger.Error("DATABASE_URL is required")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, dbURL, logger)
	stop()
	if err != nil {
		logger.Error("MCP server stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, dbURL string, logger *slog.Logger) error {
	// Conservative pool: MCP is single-user, read-only.
	poolCfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return fmt.Errorf("parsing DATABASE_URL: %w", err)
	}
	poolCfg.MaxConns = 5

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}

	noteStore := note.NewStore(pool)
	activityStore := activity.NewStore(pool)
	projectStore := project.NewStore(pool)

	server := mcpserver.NewServer(noteStore, activityStore, projectStore, logger)

	logger.Info("starting MCP server over stdio")
	return server.Run(ctx)
}
