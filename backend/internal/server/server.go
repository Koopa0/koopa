package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/koopa0/blog-backend/internal/auth"
)

// Config holds server configuration.
type Config struct {
	Port       string
	CORSOrigin string
	JWTSecret  string
}

// Run creates and starts the HTTP server with graceful shutdown.
// It blocks until ctx is cancelled, then drains connections.
func Run(ctx context.Context, cfg Config, deps Deps, logger *slog.Logger) error {
	RegisterMetrics(prometheus.DefaultRegisterer)

	authMid := auth.Middleware(cfg.JWTSecret)
	rlDone := make(chan struct{})
	rlMid := rateLimitMiddleware(logger, rlDone)

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", MetricsHandler())
	RegisterRoutes(mux, deps, authMid, rlMid)

	csrfMid, err := csrfMiddleware(cfg.CORSOrigin, logger)
	if err != nil {
		return fmt.Errorf("setting up CSRF middleware: %w", err)
	}

	// Middleware chain (outermost first):
	// prometheus → request-id → logging → security headers → CORS → CSRF → mux
	handler := prometheusMiddleware(
		requestIDMiddleware(logger)(
			loggingMiddleware(logger)(
				securityHeaders(
					corsMiddleware(cfg.CORSOrigin)(
						csrfMid(mux),
					),
				),
			),
		),
	)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("server starting", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	close(rlDone) // stop rate limiter cleanup goroutine

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}

	logger.Info("server stopped")
	return nil
}
