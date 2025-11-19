package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/koopa0/koopa-cli/cmd"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/ui"
)

const version = "1.0.0"

func main() {
	// Handle special commands (--version, --help) without entering interactive mode
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("Koopa v%s\n", version)
			fmt.Printf("Build: %s\n", cmd.BuildTime)
			fmt.Printf("Commit: %s\n", cmd.GitCommit)
			return
		case "help", "--help", "-h":
			printHelp()
			return
		}
	}

	// Initialize logger
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	if os.Getenv("DEBUG") != "" {
		opts.Level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Error loading config", "error", err)
		os.Exit(1)
	}

	// Check for GEMINI_API_KEY
	if os.Getenv("GEMINI_API_KEY") == "" {
		// This is a user-facing error, so we use fmt/ui logic or specialized error printing
		// But since we are in main and UI isn't up yet, we can use slog or fmt.
		// Let's use fmt for user instructions as it's cleaner for "how to fix".
		fmt.Fprintln(os.Stderr, "Error: GEMINI_API_KEY environment variable not set")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Please run:")
		fmt.Fprintln(os.Stderr, "  export GEMINI_API_KEY=your-api-key")
		os.Exit(1)
	}

	// Enter interactive mode (default behavior)
	ctx := context.Background()
	// Initialize UI
	term := ui.NewConsole(os.Stdin, os.Stdout)

	if err := cmd.Run(ctx, cfg, version, term); err != nil {
		slog.Error("Application error", "error", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("Koopa - Your terminal AI personal assistant")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  koopa              Start interactive chat mode (default)")
	fmt.Println("  koopa --version    Show version information")
	fmt.Println("  koopa --help       Show this help")
	fmt.Println()
	fmt.Println("Interactive Commands:")
	fmt.Println("  System:")
	fmt.Println("    /help            Show available commands")
	fmt.Println("    /version         Show version")
	fmt.Println("    /clear           Clear conversation history")
	fmt.Println("    /exit, /quit     Exit Koopa")
	fmt.Println()
	fmt.Println("  RAG (Knowledge):")
	fmt.Println("    /rag status      Show RAG system status")
	fmt.Println("    /rag add <path>  Index a file or directory")
	fmt.Println("    /rag list        List indexed documents")
	fmt.Println("    /rag remove <id> Remove a document")
	fmt.Println()
	fmt.Println("  Shortcuts:")
	fmt.Println("    Ctrl+D           Exit Koopa")
	fmt.Println("    Ctrl+C           Cancel current input")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  GEMINI_API_KEY     Required: Gemini API key")
	fmt.Println()
	fmt.Println("Learn more: https://github.com/koopa0/koopa-cli")
}
