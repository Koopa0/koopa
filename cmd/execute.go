package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/ui"
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
	// Handle special flags before full initialization
	// This allows --version and --help to work even if config is invalid
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			return printVersionInfo()
		case "help", "--help", "-h":
			printHelp()
			return nil
		case "mcp":
			// MCP server mode requires full initialization
			return executeMCP()
		case "serve":
			// HTTP API server mode
			return executeServe()
		default:
			// Check if it's an unknown command (starts without -)
			if !strings.HasPrefix(os.Args[1], "-") {
				fmt.Fprintf(os.Stderr, "Error: unknown command %q\n", os.Args[1])
				fmt.Fprintln(os.Stderr, "Run 'koopa --help' for usage.")
				return fmt.Errorf("unknown command: %s", os.Args[1])
			}
		}
	}

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

	// Enter interactive mode (default behavior)
	// Use signal-based context for graceful shutdown on Ctrl+C
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	term := ui.NewConsole(os.Stdin, os.Stdout)

	return Run(ctx, cfg, AppVersion, term)
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
	if err := checkRequiredEnv(); err != nil {
		return err
	}

	// Parse address from args or use default
	addr := "127.0.0.1:3400"
	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "--addr" || arg == "-a" {
			if i+1 < len(os.Args) {
				addr = os.Args[i+1]
			}
			break
		}
		// Support --addr=:8080 format
		if len(arg) > 7 && arg[:7] == "--addr=" {
			addr = arg[7:]
			break
		}
	}

	// Validate address format
	if err := validateAddr(addr); err != nil {
		return fmt.Errorf("invalid address %q: %w", addr, err)
	}

	// Start HTTP API server
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return RunServe(ctx, cfg, AppVersion, addr)
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
	fmt.Println("  koopa              Start interactive chat mode (default)")
	fmt.Println("  koopa serve [addr] Start HTTP API server (default: 127.0.0.1:3400)")
	fmt.Println("  koopa mcp          Start MCP server (for Claude Desktop/Cursor)")
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
	fmt.Println("  Session:")
	fmt.Println("    /session         Show current session")
	fmt.Println("    /session list    List all sessions")
	fmt.Println("    /session new     Create new session")
	fmt.Println()
	fmt.Println("  Shortcuts:")
	fmt.Println("    Ctrl+D           Exit Koopa")
	fmt.Println("    Ctrl+C           Cancel current input")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  GEMINI_API_KEY     Required: Gemini API key")
	fmt.Println("  DEBUG              Optional: Enable debug logging")
	fmt.Println()
	fmt.Println("Learn more: https://github.com/koopa0/koopa-cli")
}
