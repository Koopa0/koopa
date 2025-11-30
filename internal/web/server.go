// Package web provides the GenUI web server and HTTP handlers.
package web

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/web/handlers"
	"github.com/koopa0/koopa-cli/internal/web/static"
)

// Server is the GenUI HTTP server.
type Server struct {
	mux    *http.ServeMux
	logger *slog.Logger
	isDev  bool
}

// ServerDeps contains dependencies for creating a GenUI server.
type ServerDeps struct {
	Logger       *slog.Logger
	ChatFlow     *chat.Flow     // Optional: nil enables simulation mode
	SessionStore *session.Store // Required: PostgreSQL session store
	CSRFSecret   []byte         // Required: 32+ byte HMAC secret
	IsDev        bool           // Optional: enables relaxed CSP for E2E testing
}

// NewServer creates a new GenUI server with all routes configured.
// If deps.ChatFlow is nil, the chat handler operates in simulation mode.
// Returns an error if required dependencies are missing.
func NewServer(deps ServerDeps) (*Server, error) {
	// Validate required dependencies
	if deps.SessionStore == nil {
		return nil, errors.New("SessionStore is required")
	}
	if len(deps.CSRFSecret) < 32 {
		return nil, errors.New("CSRFSecret must be at least 32 bytes")
	}

	mux := http.NewServeMux()
	s := &Server{
		mux:    mux,
		logger: deps.Logger,
		isDev:  deps.IsDev,
	}

	// Initialize session handler
	sessions := handlers.NewSessions(deps.SessionStore, deps.CSRFSecret)

	// Initialize health handler
	health := handlers.NewHealth()

	// Initialize handlers
	pages := handlers.NewPages(handlers.PagesDeps{
		Logger:   deps.Logger,
		Sessions: sessions,
	})
	chatHandler := handlers.NewChat(handlers.ChatDeps{
		Logger:   deps.Logger,
		Flow:     deps.ChatFlow,
		Sessions: sessions,
	})

	// Health check routes (no middleware - for Docker/K8s probes)
	health.RegisterRoutes(mux)

	// Session management routes
	sessions.RegisterRoutes(mux)

	// Page routes
	mux.HandleFunc("GET /genui", pages.Chat)
	mux.HandleFunc("GET /genui/", pages.Chat)

	// Chat API routes
	mux.HandleFunc("POST /genui/chat/send", chatHandler.Send)
	mux.HandleFunc("GET /genui/stream", chatHandler.Stream)

	// Static assets
	mux.Handle("GET /genui/static/", http.StripPrefix("/genui/static/", static.Handler()))

	return s, nil
}

// ServeHTTP implements http.Handler with middleware stack.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Apply security headers
	s.setSecurityHeaders(w)

	// Apply middleware stack: Recovery → Logging → Routes
	var handler http.Handler = s.mux
	if s.logger != nil {
		handler = LoggingMiddleware(s.logger)(handler)
		handler = RecoveryMiddleware(s.logger)(handler)
	}

	handler.ServeHTTP(w, r)
}

// setSecurityHeaders applies security headers for the GenUI interface.
func (s *Server) setSecurityHeaders(w http.ResponseWriter) {
	// CSP: HTMX needs unsafe-inline for event handlers (hx-on::*)
	// Tailwind may inject inline styles
	csp := "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline'"

	// In dev/test mode, allow eval for debugging tools (axe-core, etc.)
	if s.isDev {
		csp += " 'unsafe-eval'"
	}

	csp += "; style-src 'self' 'unsafe-inline'; connect-src 'self'"
	w.Header().Set("Content-Security-Policy", csp)

	// Prevent MIME type sniffing
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Prevent clickjacking
	w.Header().Set("X-Frame-Options", "DENY")

	// Referrer policy
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

// Handler returns the server as an http.Handler for mounting.
func (s *Server) Handler() http.Handler {
	return s
}
