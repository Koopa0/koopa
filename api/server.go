// Package api provides HTTP REST API for Koopa.
//
// This package exposes Koopa's functionality via HTTP endpoints,
// enabling programmatic access from external tools and automation pipelines.
//
// Architecture:
//
//	┌─────────────────────────────────────────────────────────┐
//	│                      API Endpoints                      │
//	├─────────────────────────────────────────────────────────┤
//	│                                                         │
//	│  Flow-based (via genkit.Handler):                       │
//	│  ─────────────────────────────────                      │
//	│  POST /api/chat  →  genkit.Handler(koopa/chat Flow)     │
//	│                                                         │
//	│  Non-Flow (standard HTTP handlers):                     │
//	│  ────────────────────────────────                       │
//	│  GET  /health        →  liveness probe                  │
//	│  GET  /ready         →  readiness probe                 │
//	│  GET  /api/sessions  →  list sessions                   │
//	│  POST /api/sessions  →  create session                  │
//	│                                                         │
//	└─────────────────────────────────────────────────────────┘
//
// File structure:
//   - server.go: HTTP server setup and lifecycle
//   - middleware.go: HTTP middleware (logging, recovery)
//   - health.go: Health check endpoints (/health, /ready)
//   - session.go: Session management endpoints (CRUD)
//   - chat.go: Chat endpoint via Genkit Flow
//   - response.go: JSON response helpers
package api

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/log"
	"github.com/koopa0/koopa-cli/internal/session"
)

const (
	// DefaultAddr is the default address for the HTTP server.
	DefaultAddr = "127.0.0.1:3400"

	// ShutdownTimeout is the maximum time to wait for graceful shutdown.
	ShutdownTimeout = 10 * time.Second

	// ReadHeaderTimeout is the timeout for reading request headers.
	// This prevents Slowloris attacks (CWE-400).
	ReadHeaderTimeout = 10 * time.Second

	// ReadTimeout is the maximum duration for reading the entire request.
	ReadTimeout = 30 * time.Second

	// WriteTimeout is the maximum duration for writing the response.
	WriteTimeout = 60 * time.Second

	// IdleTimeout is the maximum time to wait for the next request on keep-alive connections.
	IdleTimeout = 120 * time.Second
)

// Server is the HTTP server for Koopa's REST API.
type Server struct {
	mux    *http.ServeMux
	logger log.Logger

	// Handlers
	health  *HealthHandler
	session *SessionHandler
	chat    *ChatHandler
}

// NewServer creates a new HTTP server with all routes registered.
// pool is used for health checks (readiness probe).
// chatFlow is obtained from chat.DefineFlow() and used for the /api/chat endpoint.
// logger is injected for structured logging (use log.NewNop() in tests).
//
// Note: nil parameters are handled gracefully:
//   - pool nil: /ready returns 503 (unhealthy)
//   - store nil: session endpoints return 500
//   - chatFlow nil: /api/chat not registered (returns 404)
//   - logger nil: uses log.NewNop() to prevent panics
func NewServer(pool *pgxpool.Pool, store *session.Store, chatFlow *chat.Flow, logger log.Logger) *Server {
	// Use nop logger if nil to prevent panics in middleware
	if logger == nil {
		logger = log.NewNop()
	}

	mux := http.NewServeMux()

	s := &Server{
		mux:     mux,
		logger:  logger,
		health:  NewHealthHandler(pool, logger),
		session: NewSessionHandler(store, logger),
		chat:    NewChatHandler(chatFlow, logger),
	}

	// Register all routes
	s.health.RegisterRoutes(mux)
	s.session.RegisterRoutes(mux)
	s.chat.RegisterRoutes(mux)

	return s
}

// Handler returns the HTTP handler with middleware applied.
// Middleware order: recovery → logging → handler
func (s *Server) Handler() http.Handler {
	return chain(s.mux,
		recoveryMiddleware(s.logger),
		loggingMiddleware(s.logger),
	)
}

// Run starts the HTTP server and blocks until the context is cancelled.
// It handles graceful shutdown when the context is done.
func (s *Server) Run(ctx context.Context, addr string) error {
	if addr == "" {
		addr = DefaultAddr
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("starting HTTP server", "addr", addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("shutting down HTTP server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		// Wait for the goroutine to exit to prevent goroutine leak
		<-errCh
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
