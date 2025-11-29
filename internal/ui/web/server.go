// Package web provides the GenUI web server and HTTP handlers.
package web

import (
	"log/slog"
	"net/http"

	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/ui/web/handlers"
	"github.com/koopa0/koopa-cli/internal/ui/web/static"
)

// Server is the GenUI HTTP server.
type Server struct {
	mux    *http.ServeMux
	logger *slog.Logger
}

// ServerDeps contains dependencies for creating a GenUI server.
type ServerDeps struct {
	Logger   *slog.Logger
	ChatFlow *chat.Flow // Optional: nil enables simulation mode
}

// NewServer creates a new GenUI server with all routes configured.
// If deps.ChatFlow is nil, the chat handler operates in simulation mode.
func NewServer(deps ServerDeps) *Server {
	mux := http.NewServeMux()
	s := &Server{mux: mux, logger: deps.Logger}

	// Initialize handlers
	pages := handlers.NewPages(deps.Logger)
	chatHandler := handlers.NewChat(deps.Logger, deps.ChatFlow)

	// Page routes
	mux.HandleFunc("GET /genui", pages.Chat)
	mux.HandleFunc("GET /genui/", pages.Chat)

	// Chat API routes
	mux.HandleFunc("POST /genui/chat/send", chatHandler.Send)
	mux.HandleFunc("GET /genui/stream", chatHandler.Stream)

	// Static assets
	mux.Handle("GET /genui/static/", http.StripPrefix("/genui/static/", static.Handler()))

	return s
}

// ServeHTTP implements http.Handler with security middleware.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Apply security headers
	s.setSecurityHeaders(w)
	s.mux.ServeHTTP(w, r)
}

// setSecurityHeaders applies security headers for the GenUI interface.
func (*Server) setSecurityHeaders(w http.ResponseWriter) {
	// CSP: HTMX needs unsafe-inline for event handlers (hx-on::*)
	// Tailwind may inject inline styles
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' 'unsafe-inline'; "+
			"style-src 'self' 'unsafe-inline'; "+
			"connect-src 'self'")

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
