package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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

// ErrMissingHMACSecret indicates HMAC_SECRET is not configured for serve mode.
var ErrMissingHMACSecret = errors.New("HMAC_SECRET environment variable is required for serve mode (min 32 characters)")

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
		return ErrMissingHMACSecret
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
	defer runtime.Cleanup()
	defer func() {
		if shutdownErr := runtime.Shutdown(); shutdownErr != nil {
			logger.Warn("failed to shutdown runtime", "error", shutdownErr)
		}
	}()

	// Create web server (GenUI + Health checks)
	webServer, err := web.NewServer(web.ServerDeps{
		Logger:       logger,
		ChatFlow:     runtime.Flow,
		SessionStore: runtime.App.SessionStore,
		CSRFSecret:   []byte(cfg.HMACSecret),
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
