package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/koopa0/koopa-cli/internal/app"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/web"
)

// Server timeout configuration.
const (
	ReadHeaderTimeout = 10 * time.Second
	ReadTimeout       = 30 * time.Second
	WriteTimeout      = 2 * time.Minute // SSE streaming needs longer timeout
	IdleTimeout       = 120 * time.Second
	ShutdownTimeout   = 30 * time.Second
)

// RunServe starts the HTTP web server (GenUI + Health checks).
//
// Architecture:
//   - Validates required configuration (HMAC_SECRET)
//   - Initializes the application runtime
//   - Creates the web server with all routes
//   - Signal handling is done by caller (executeServe)
func RunServe(ctx context.Context, cfg *config.Config, version, addr string) error {
	logger := slog.Default()

	// Validate HMAC_SECRET for serve mode
	if cfg.HMACSecret == "" {
		return errors.New("HMAC_SECRET environment variable is required for serve mode (min 32 characters)")
	}
	if len(cfg.HMACSecret) < 32 {
		return fmt.Errorf("HMAC_SECRET must be at least 32 characters, got %d", len(cfg.HMACSecret))
	}

	logger.Info("starting HTTP web server", "version", version)

	// Initialize runtime with all components
	runtime, err := app.NewRuntime(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize runtime: %w", err)
	}
	defer func() {
		if closeErr := runtime.Close(); closeErr != nil {
			logger.Warn("runtime close error", "error", closeErr)
		}
	}()

	// Create web server (GenUI + Health checks)
	webServer, err := web.NewServer(web.ServerConfig{
		Logger:       logger,
		Genkit:       runtime.App.Genkit,
		ChatFlow:     runtime.Flow,
		SessionStore: runtime.App.SessionStore,
		CSRFSecret:   []byte(cfg.HMACSecret),
		Config:       cfg,
	})
	if err != nil {
		return fmt.Errorf("failed to create web server: %w", err)
	}

	// Create HTTP server
	srv := &http.Server{
		Addr:              addr,
		Handler:           webServer.Handler(),
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
	}

	logger.Info("HTTP server ready",
		"addr", addr,
		"genui", "/genui/*",
		"health", "/health, /ready",
	)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down HTTP server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown failed: %w", err)
		}
		<-errCh
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// runServe initializes and starts the HTTP API server.
// This is called when the user runs `koopa serve`.
func runServe() error {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}

	addr, err := parseServeAddr()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return RunServe(ctx, cfg, Version, addr)
}

// parseServeAddr parses and validates the server address from command line arguments.
// Uses flag.FlagSet for standard Go flag parsing, supporting:
//   - koopa serve :8080           (positional)
//   - koopa serve --addr :8080    (flag)
//   - koopa serve -addr :8080     (single dash)
func parseServeAddr() (string, error) {
	const defaultAddr = "127.0.0.1:3400"

	serveFlags := flag.NewFlagSet("serve", flag.ContinueOnError)
	serveFlags.SetOutput(os.Stderr)

	addr := serveFlags.String("addr", defaultAddr, "Server address (host:port)")

	args := []string{}
	if len(os.Args) > 2 {
		args = os.Args[2:]
	}

	// Check for positional argument first (koopa serve :8080)
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		*addr = args[0]
		args = args[1:]
	}

	if err := serveFlags.Parse(args); err != nil {
		return "", fmt.Errorf("failed to parse serve flags: %w", err)
	}

	if err := validateAddr(*addr); err != nil {
		return "", fmt.Errorf("invalid address %q: %w", *addr, err)
	}

	return *addr, nil
}

// validateAddr validates the server address format.
func validateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("must be in host:port format: %w", err)
	}

	if host != "" && host != "localhost" {
		if ip := net.ParseIP(host); ip == nil {
			if strings.ContainsAny(host, " \t\n") {
				return fmt.Errorf("invalid host: %s", host)
			}
		}
	}

	if port == "" {
		return fmt.Errorf("port is required")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port must be numeric: %w", err)
	}
	if portNum < 0 || portNum > 65535 {
		return fmt.Errorf("port must be 0-65535 (0 = auto-assign), got %d", portNum)
	}

	return nil
}
