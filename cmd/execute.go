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
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	tea "charm.land/bubbletea/v2"

	"github.com/koopa0/koopa-cli/internal/app"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/tui"
)

// Version information (injected at build time via ldflags).
// These variables are set by the build system and should not be modified directly.
var (
	AppVersion = "0.0.1"
	BuildTime  = "unknown"
	GitCommit  = "unknown"
)

// Execute is the main entry point for the Koopa CLI application.
// It handles all initialization, flag parsing, and command routing.
//
// This function is designed to be called from main() and is also
// testable in unit tests.
//
// Design: Following the pattern used by kubectl, hugo, and other
// standard Go CLI tools, all application logic is contained in
// the cmd package, leaving main.go as a minimal entry point.
func Execute() error {
	// Handle subcommands and flags
	// This allows --version and --help to work even if config is invalid
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			return printVersionInfo()
		case "help", "--help", "-h":
			printHelp()
			return nil
		case "cli":
			// Interactive CLI mode
			return executeCLI()
		case "mcp":
			// MCP server mode
			return executeMCP()
		case "serve":
			// HTTP API server mode
			return executeServe()
		default:
			// Unknown command or flag
			fmt.Fprintf(os.Stderr, "Error: unknown command %q\n", os.Args[1])
			fmt.Fprintln(os.Stderr, "Run 'koopa --help' for usage.")
			return fmt.Errorf("unknown command: %s", os.Args[1])
		}
	}

	// No arguments: show help (explicit subcommand required)
	printHelp()
	return nil
}

// executeCLI initializes and starts the interactive CLI with Bubble Tea TUI.
// This is called when the user runs `koopa cli`.
func executeCLI() error {
	// Initialize structured logger
	logger := initLogger()
	slog.SetDefault(logger)

	// Load application configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Verify required environment variables
	if envErr := checkRequiredEnv(); envErr != nil {
		return envErr
	}

	// Create context with signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Initialize runtime with all components
	runtime, err := app.NewRuntime(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize runtime: %w", err)
	}
	defer runtime.Cleanup()
	defer func() {
		if shutdownErr := runtime.Shutdown(); shutdownErr != nil {
			slog.Warn("failed to shutdown runtime", "error", shutdownErr)
		}
	}()

	// Get or create session
	sessionID, err := getOrCreateSessionID(ctx, runtime.App.SessionStore, cfg)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Create TUI model (direct dependency on *chat.Flow)
	// IMPORTANT: ctx MUST match tea.WithContext(ctx) for consistent cancellation
	model := tui.New(ctx, runtime.Flow, sessionID)

	// Run Bubble Tea program
	// Note: In v2, AltScreen is controlled via View.AltScreen = true
	program := tea.NewProgram(
		model,
		tea.WithContext(ctx),
	)

	_, err = program.Run()
	if err != nil {
		return fmt.Errorf("TUI exited: %w", err)
	}
	return nil
}

// getOrCreateSessionID returns a valid session ID, creating a new session if needed.
func getOrCreateSessionID(ctx context.Context, store *session.Store, cfg *config.Config) (string, error) {
	currentID, err := session.LoadCurrentSessionID()
	if err != nil {
		return "", fmt.Errorf("failed to load session: %w", err)
	}

	if currentID != nil {
		if _, err = store.GetSession(ctx, *currentID); err == nil {
			return currentID.String(), nil
		}
		if !errors.Is(err, session.ErrSessionNotFound) {
			return "", fmt.Errorf("failed to validate session: %w", err)
		}
	}

	// Create new session
	newSess, err := store.CreateSession(ctx, "New Session", cfg.ModelName, "You are a helpful assistant.")
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	if err := session.SaveCurrentSessionID(newSess.ID); err != nil {
		slog.Warn("failed to save session state", "error", err)
	}

	return newSess.ID.String(), nil
}

// initLogger initializes the structured logger with appropriate log level.
//
// Log level is controlled by the DEBUG environment variable:
//   - DEBUG set (any value): debug level logging
//   - DEBUG not set: info level logging
//
// Design: Follows the standard library's slog package patterns.
// Note: Logs to stderr for MCP protocol compatibility (stdout reserved for JSON-RPC).
func initLogger() *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	// Enable debug logging if DEBUG env var is set
	if os.Getenv("DEBUG") != "" {
		opts.Level = slog.LevelDebug
	}

	// IMPORTANT: MCP protocol requires logging to stderr, not stdout
	// stdout is reserved for JSON-RPC messages only
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// checkRequiredEnv verifies that all required environment variables are set.
//
// Currently checks:
//   - GEMINI_API_KEY: Required for AI model access
//
// Returns a user-friendly error with setup instructions if validation fails.
func checkRequiredEnv() error {
	if os.Getenv("GEMINI_API_KEY") == "" {
		// Print user-friendly error message to stderr
		fmt.Fprintln(os.Stderr, "Error: GEMINI_API_KEY environment variable not set")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Koopa requires a Gemini API key to function.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "To set your API key:")
		fmt.Fprintln(os.Stderr, "  export GEMINI_API_KEY=your-api-key")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Get your API key at: https://ai.google.dev/")

		return fmt.Errorf("GEMINI_API_KEY not set")
	}
	return nil
}

// printVersionInfo displays version information and exits.
// This is called for --version flags.
func printVersionInfo() error {
	fmt.Printf("Koopa v%s\n", AppVersion)
	fmt.Printf("Build: %s\n", BuildTime)
	fmt.Printf("Commit: %s\n", GitCommit)
	return nil
}

// executeMCP initializes and starts the MCP server.
// This is called when the user runs `koopa mcp`.
func executeMCP() error {
	// Initialize structured logger
	logger := initLogger()
	slog.SetDefault(logger)

	// Load application configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Verify required environment variables
	if err := checkRequiredEnv(); err != nil {
		return err
	}

	// Start MCP server with signal-based context
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return RunMCP(ctx, cfg, AppVersion)
}

// executeServe initializes and starts the HTTP API server.
// This is called when the user runs `koopa serve`.
func executeServe() error {
	// Initialize structured logger
	logger := initLogger()
	slog.SetDefault(logger)

	// Load application configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Verify required environment variables
	if envErr := checkRequiredEnv(); envErr != nil {
		return envErr
	}

	// Parse and validate address from args or use default
	addr, err := parseServeAddr()
	if err != nil {
		return err
	}

	// Start HTTP API server
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return RunServe(ctx, cfg, AppVersion, addr)
}

// parseServeAddr parses and validates the server address from command line arguments.
// Uses flag.FlagSet for standard Go flag parsing, supporting:
//   - koopa serve :8080           (positional)
//   - koopa serve --addr :8080    (flag)
//   - koopa serve -addr :8080     (single dash)
//
// Returns error if address format is invalid.
func parseServeAddr() (string, error) {
	// defaultAddr uses port 3400 to avoid conflicts with common services:
	//   - 3000: Node.js dev servers
	//   - 8080: Common HTTP alt port
	const defaultAddr = "127.0.0.1:3400"

	// Create a FlagSet for the serve subcommand
	serveFlags := flag.NewFlagSet("serve", flag.ContinueOnError)
	serveFlags.SetOutput(os.Stderr)

	// Define flags
	addr := serveFlags.String("addr", defaultAddr, "Server address (host:port)")

	// Parse flags starting from os.Args[2] (after "koopa serve")
	args := []string{}
	if len(os.Args) > 2 {
		args = os.Args[2:]
	}

	// Check for positional argument first (koopa serve :8080)
	// If first arg doesn't start with "-", treat it as positional
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		*addr = args[0]
		args = args[1:] // Remove positional from args for further parsing
	}

	// Parse remaining flags (allows mixing positional and flags)
	if err := serveFlags.Parse(args); err != nil {
		return "", fmt.Errorf("failed to parse serve flags: %w", err)
	}

	// Validate address format
	if err := validateAddr(*addr); err != nil {
		return "", fmt.Errorf("invalid address %q: %w", *addr, err)
	}

	return *addr, nil
}

// validateAddr validates the server address format.
// Accepts formats: "host:port", ":port", or "host:port".
func validateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("must be in host:port format: %w", err)
	}

	// Validate host if provided
	if host != "" && host != "localhost" {
		if ip := net.ParseIP(host); ip == nil {
			// Not a valid IP, check if it's a valid hostname
			if strings.ContainsAny(host, " \t\n") {
				return fmt.Errorf("invalid host: %s", host)
			}
		}
	}

	// Validate port
	if port == "" {
		return fmt.Errorf("port is required")
	}

	return nil
}

// printHelp displays the help message for the Koopa CLI.
// This is called for --help flags or when run without arguments.
func printHelp() {
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
	fmt.Println("Learn more: https://github.com/koopa0/koopa-cli")
}
