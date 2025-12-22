// Package cmd provides CLI commands for Koopa.
//
// Commands:
//   - cli: Interactive terminal chat with Bubble Tea TUI
//   - serve: HTTP API server with SSE streaming
//   - mcp: Model Context Protocol server for IDE integration
//
// Signal handling and graceful shutdown are implemented
// for all commands via context cancellation.
package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/koopa0/koopa/internal/log"
)

// Version is set at build time via ldflags:
//
//	go build -ldflags "-X github.com/koopa0/koopa/cmd.Version=1.0.0"
//
// Default value "dev" indicates a development build.
var Version = "dev"

// Execute is the main entry point for the Koopa CLI application.
func Execute() error {
	// Initialize logger once at entry point
	level := slog.LevelInfo
	if os.Getenv("DEBUG") != "" {
		level = slog.LevelDebug
	}
	slog.SetDefault(log.New(log.Config{Level: level}))

	if len(os.Args) < 2 {
		runHelp()
		return nil
	}

	switch os.Args[1] {
	case "cli":
		return runCLI()
	case "serve":
		return runServe()
	case "mcp":
		return runMCP()
	case "version", "--version", "-v":
		runVersion()
		return nil
	case "help", "--help", "-h":
		runHelp()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n", os.Args[1])
		return fmt.Errorf("unknown command: %s", os.Args[1])
	}
}
