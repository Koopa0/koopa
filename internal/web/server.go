// Package web provides the GenUI web server and HTTP handlers.
package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/web/handlers"
	"github.com/koopa0/koopa-cli/internal/web/static"
)

// Server is the GenUI HTTP server.
type Server struct {
	mux      *http.ServeMux
	logger   *slog.Logger
	sessions *handlers.Sessions
	isDev    bool
}

// ServerConfig contains configuration for creating a GenUI server.
type ServerConfig struct {
	Logger       *slog.Logger
	Genkit       *genkit.Genkit // Optional: nil disables AI title generation (falls back to truncation)
	ChatFlow     *chat.Flow     // Optional: nil enables simulation mode
	SessionStore *session.Store // Required: PostgreSQL session store
	CSRFSecret   []byte         // Required: 32+ byte HMAC secret
	Config       *config.Config // Required: application configuration
	IsDev        bool           // Optional: enables relaxed CSP for E2E testing
}

// NewServer creates a new GenUI server with all routes configured.
// If cfg.ChatFlow is nil, the chat handler operates in simulation mode.
// Returns an error if required configuration is missing.
func NewServer(cfg ServerConfig) (*Server, error) {
	// Validate required configuration
	if cfg.SessionStore == nil {
		return nil, errors.New("SessionStore is required")
	}
	if len(cfg.CSRFSecret) < 32 {
		return nil, errors.New("CSRFSecret must be at least 32 bytes")
	}
	if cfg.Config == nil {
		return nil, errors.New("config is required")
	}

	mux := http.NewServeMux()

	// Initialize session handler
	// isDev enables HTTP cookies (Secure=false) for local development
	sessions := handlers.NewSessions(cfg.SessionStore, cfg.CSRFSecret, cfg.IsDev)

	s := &Server{
		mux:      mux,
		logger:   cfg.Logger,
		sessions: sessions,
		isDev:    cfg.IsDev,
	}

	// Initialize health handler
	health := handlers.NewHealth()

	// Initialize handlers
	pages := handlers.NewPages(handlers.PagesConfig{
		Logger:   cfg.Logger,
		Sessions: sessions,
	})
	chatHandler := handlers.NewChat(handlers.ChatConfig{
		Logger:   cfg.Logger,
		Genkit:   cfg.Genkit,
		Flow:     cfg.ChatFlow,
		Sessions: sessions,
	})
	modeHandler := handlers.NewMode(handlers.ModeConfig{
		Sessions: sessions,
	})
	// TODO: Implement Settings and Search handlers
	// settingsHandler := handlers.NewSettings(handlers.SettingsDeps{
	// 	Logger:   deps.Logger,
	// 	Config:   deps.Config,
	// 	Sessions: sessions,
	// })
	// searchHandler := handlers.NewSearch(handlers.SearchDeps{
	// 	Logger:       deps.Logger,
	// 	SessionStore: deps.SessionStore,
	// 	Sessions:     sessions,
	// })

	// Health check routes (no middleware - for Docker/K8s probes)
	health.RegisterRoutes(mux)

	// Session management routes
	sessions.RegisterRoutes(mux)

	// Page routes
	mux.HandleFunc("GET /genui", pages.Chat)
	mux.HandleFunc("GET /genui/", pages.Chat)

	// Chat API routes (matches hx-post in chat_input.templ)
	mux.HandleFunc("POST /genui/send", chatHandler.Send)
	mux.HandleFunc("GET /genui/stream", chatHandler.Stream)

	// Mode toggle route (canvas/chat mode)
	modeHandler.RegisterRoutes(mux)

	// TODO: Settings and Search routes
	// settingsHandler.RegisterRoutes(mux)
	// searchHandler.RegisterRoutes(mux)

	// Static assets
	mux.Handle("GET /genui/static/", http.StripPrefix("/genui/static/", static.Handler()))

	return s, nil
}

// ServeHTTP implements http.Handler with middleware stack.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Apply security headers
	s.setSecurityHeaders(w)

	// Static files don't need session/CSRF middleware (performance + test compatibility)
	if strings.HasPrefix(r.URL.Path, "/genui/static/") {
		if s.logger != nil {
			// Only apply logging and recovery for static files
			handler := LoggingMiddleware(s.logger)(RecoveryMiddleware(s.logger)(s.mux))
			handler.ServeHTTP(w, r)
		} else {
			s.mux.ServeHTTP(w, r)
		}
		return
	}

	// Apply full middleware stack for dynamic routes:
	// Recovery → Logging → MethodOverride → Session → CSRF → Routes
	// Order matters: Recovery catches panics, Logging tracks requests,
	// MethodOverride converts POST+_method to DELETE/PUT (before CSRF checks method),
	// Session creates/validates session cookies, CSRF validates tokens for mutations
	var handler http.Handler = s.mux
	if s.logger != nil {
		// CSRF validation (requires Session context)
		handler = RequireCSRF(s.sessions, s.logger)(handler)
		// Session management (injects session ID into context)
		handler = RequireSession(s.sessions, s.logger)(handler)
		// Method override (converts POST+_method to DELETE/PUT for form compatibility)
		handler = MethodOverride(handler)
		// Logging (tracks all requests)
		handler = LoggingMiddleware(s.logger)(handler)
		// Recovery (catches panics from any layer below)
		handler = RecoveryMiddleware(s.logger)(handler)
	}

	handler.ServeHTTP(w, r)
}

// setSecurityHeaders applies security headers for the GenUI interface.
func (s *Server) setSecurityHeaders(w http.ResponseWriter) {
	// CSP: HTMX needs unsafe-inline for event handlers (hx-on::*)
	// Tailwind may inject inline styles
	// All JS assets are now vendored locally (no CDN dependencies)
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
