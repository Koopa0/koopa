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
)

// Execute is the main entry point for the Koopa CLI application.
func Execute() error {
	// Initialize logger once at entry point
	level := slog.LevelInfo
	if os.Getenv("DEBUG") != "" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

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
		return fmt.Errorf("unknown command: %s", os.Args[1])
	}
}

// runHelp displays the help message.
func runHelp() {
	fmt.Println("Koopa - Your terminal AI personal assistant")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  koopa cli          Start interactive chat mode")
	fmt.Println("  koopa serve [addr] Start HTTP API server (default: 127.0.0.1:3400)")
	fmt.Println("  koopa mcp          Start MCP server (for Claude Desktop/Cursor)")
	fmt.Println("  koopa --version    Show version information")
	fmt.Println("  koopa --help       Show this help")
	fmt.Println()
	fmt.Println("CLI Commands (in interactive mode):")
	fmt.Println("  /help              Show available commands")
	fmt.Println("  /version           Show version")
	fmt.Println("  /clear             Clear conversation history")
	fmt.Println("  /exit, /quit       Exit Koopa")
	fmt.Println()
	fmt.Println("Shortcuts:")
	fmt.Println("  Ctrl+D             Exit Koopa")
	fmt.Println("  Ctrl+C             Cancel current input")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  GEMINI_API_KEY     Required: Gemini API key")
	fmt.Println("  DEBUG              Optional: Enable debug logging")
	fmt.Println()
	fmt.Println("Learn more: https://github.com/koopa0/koopa")
}
