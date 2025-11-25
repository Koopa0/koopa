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
	"log/slog"
	"net/http"
	"time"

	"github.com/koopa0/koopa-cli/internal/agent/chat"
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
	mux *http.ServeMux

	// Handlers
	health  *HealthHandler
	session *SessionHandler
	chat    *ChatHandler
}

// NewServer creates a new HTTP server with all routes registered.
// chatFlow is obtained from chat.DefineFlow() and used for the /api/chat endpoint.
func NewServer(store *session.Store, chatFlow *chat.Flow) *Server {
	mux := http.NewServeMux()

	s := &Server{
		mux:     mux,
		health:  NewHealthHandler(store),
		session: NewSessionHandler(store),
		chat:    NewChatHandler(chatFlow),
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
	return chain(s.mux, recoveryMiddleware, loggingMiddleware)
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
		slog.Info("starting HTTP server", "addr", addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down HTTP server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
