package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/koopa0/koopa/internal/chat"
	"github.com/koopa0/koopa/internal/session"
)

// ServerConfig contains configuration for creating the API server.
type ServerConfig struct {
	Logger       *slog.Logger
	ChatAgent    *chat.Agent    // Optional: nil disables AI title generation
	ChatFlow     *chat.Flow     // Optional: nil enables simulation mode
	SessionStore *session.Store // Required
	CSRFSecret   []byte         // Required: 32+ bytes
	CORSOrigins  []string       // Allowed origins for CORS
	IsDev        bool           // Enables HTTP cookies (no Secure flag)
	TrustProxy   bool           // Trust X-Real-IP/X-Forwarded-For headers (behind reverse proxy)
	RateBurst    int            // Rate limiter burst size per IP (0 = default 60)
}

// Server is the JSON API HTTP server.
type Server struct {
	mux *http.ServeMux
}

// NewServer creates a new API server with all routes configured.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.SessionStore == nil {
		return nil, errors.New("session store is required")
	}
	if len(cfg.CSRFSecret) < 32 {
		return nil, errors.New("csrf secret must be at least 32 bytes")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	sm := &sessionManager{
		store:      cfg.SessionStore,
		hmacSecret: cfg.CSRFSecret,
		isDev:      cfg.IsDev,
		logger:     logger,
	}

	ch := &chatHandler{
		logger:   logger,
		agent:    cfg.ChatAgent,
		flow:     cfg.ChatFlow,
		sessions: sm,
	}

	mux := http.NewServeMux()

	// CSRF token provisioning
	mux.HandleFunc("GET /api/v1/csrf-token", sm.csrfToken)

	// Session CRUD
	mux.HandleFunc("GET /api/v1/sessions", sm.listSessions)
	mux.HandleFunc("POST /api/v1/sessions", sm.createSession)
	mux.HandleFunc("GET /api/v1/sessions/{id}", sm.getSession)
	mux.HandleFunc("GET /api/v1/sessions/{id}/messages", sm.getSessionMessages)
	mux.HandleFunc("DELETE /api/v1/sessions/{id}", sm.deleteSession)

	// Chat
	mux.HandleFunc("POST /api/v1/chat", ch.send)
	mux.HandleFunc("GET /api/v1/chat/stream", ch.stream)

	// Rate limiter: per-IP token bucket (1 token/sec refill)
	burst := cfg.RateBurst
	if burst <= 0 {
		burst = 60
	}
	rl := newRateLimiter(1.0, burst)

	// Build middleware stack: Recovery → Logging → RateLimit → CORS → User → Session → CSRF → Routes
	var handler http.Handler = mux
	handler = csrfMiddleware(sm, logger)(handler)
	handler = sessionMiddleware(sm)(handler)
	handler = userMiddleware(sm)(handler)
	handler = corsMiddleware(cfg.CORSOrigins)(handler)
	handler = rateLimitMiddleware(rl, cfg.TrustProxy, logger)(handler)
	handler = loggingMiddleware(logger)(handler)
	handler = recoveryMiddleware(logger)(handler)

	// Wrap with security headers
	isDev := cfg.IsDev
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, isDev)
		handler.ServeHTTP(w, r)
	})

	// Use a top-level mux to separate health probes from middleware stack
	topMux := http.NewServeMux()
	topMux.HandleFunc("GET /health", health)
	topMux.HandleFunc("GET /ready", health)
	topMux.Handle("/", final)

	return &Server{mux: topMux}, nil
}

// Handler returns the server as an http.Handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}
