package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/koopa0/koopa/internal/api"
	"github.com/koopa0/koopa/internal/app"
	"github.com/koopa0/koopa/internal/chat"
	"github.com/koopa0/koopa/internal/config"
)

// parseRateBurst reads KOOPA_RATE_BURST from the environment.
// Returns 0 (use default) if unset or invalid.
func parseRateBurst() int {
	v := os.Getenv("KOOPA_RATE_BURST")
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// Server timeout configuration.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 2 * time.Minute // SSE streaming needs longer timeout
	idleTimeout       = 2 * time.Minute
	shutdownTimeout   = 30 * time.Second
)

// runServe initializes and starts the HTTP API server.
func runServe() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if err = cfg.ValidateServe(); err != nil {
		return fmt.Errorf("validating config: %w", err)
	}

	addr, err := parseServeAddr()
	if err != nil {
		return fmt.Errorf("parsing address: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger := slog.Default()
	logger.Info("starting HTTP API server", "version", Version)

	a, err := app.Setup(ctx, cfg)
	if err != nil {
		return fmt.Errorf("initializing application: %w", err)
	}
	defer func() {
		if closeErr := a.Close(); closeErr != nil {
			logger.Warn("shutdown error", "error", closeErr)
		}
	}()

	agent, err := a.CreateAgent()
	if err != nil {
		return fmt.Errorf("creating agent: %w", err)
	}

	flow := chat.NewFlow(a.Genkit, agent)

	apiServer, err := api.NewServer(api.ServerConfig{
		Logger:       logger,
		ChatAgent:    agent,
		ChatFlow:     flow,
		SessionStore: a.SessionStore,
		CSRFSecret:   []byte(cfg.HMACSecret),
		CORSOrigins:  cfg.CORSOrigins,
		IsDev:        cfg.PostgresSSLMode == "disable",
		TrustProxy:   cfg.TrustProxy,
		RateBurst:    parseRateBurst(),
	})
	if err != nil {
		return fmt.Errorf("creating API server: %w", err)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	logger.Info("HTTP server ready",
		"addr", addr,
		"api", "/api/v1/*",
		"health", "/health, /ready",
	)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down HTTP server")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutting down server: %w", err)
		}
		<-errCh
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("HTTP server: %w", err)
	}
}
