package api

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// sessionIDKey is an unexported context key type to prevent collisions.
type sessionIDKey struct{}

var ctxKeySessionID = sessionIDKey{}

// SessionIDFromContext retrieves the session ID from the request context.
// Returns uuid.Nil and false if not found.
func SessionIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	sessionID, ok := ctx.Value(ctxKeySessionID).(uuid.UUID)
	return sessionID, ok
}

// loggingWriter wraps http.ResponseWriter to capture metrics.
// Implements Flusher for SSE streaming and Unwrap for ResponseController.
type loggingWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (w *loggingWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

//nolint:wrapcheck // http.ResponseWriter wrapper must return unwrapped errors
func (w *loggingWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}

// Flush implements http.Flusher for SSE streaming support.
func (w *loggingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter for http.ResponseController.
func (w *loggingWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// recoveryMiddleware recovers from panics to prevent server crashes.
func recoveryMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrapper := &loggingWriter{
				ResponseWriter: w,
				statusCode:     0,
			}

			defer func() {
				if err := recover(); err != nil {
					logger.Error("panic recovered",
						"error", err,
						"path", r.URL.Path,
						"headers_sent", wrapper.statusCode != 0,
					)

					if wrapper.statusCode == 0 {
						WriteError(w, http.StatusInternalServerError, "internal_error", "internal server error")
					} else {
						logger.Warn("cannot send error response, headers already sent",
							"path", r.URL.Path,
							"status", wrapper.statusCode,
						)
					}
				}
			}()
			next.ServeHTTP(wrapper, r)
		})
	}
}

// loggingMiddleware logs request details including latency, status, and response size.
func loggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			wrapper := &loggingWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(wrapper, r)

			logger.Debug("http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapper.statusCode,
				"bytes", wrapper.bytesWritten,
				"duration", time.Since(start),
				"ip", r.RemoteAddr,
			)
		})
	}
}

// corsMiddleware handles CORS preflight and response headers.
// allowedOrigins is a list of origins permitted to access the API.
func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	originSet := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[o] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if _, ok := originSet[origin]; ok {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Max-Age", "3600")
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// sessionMiddleware ensures a valid session exists before processing the request.
// GET/HEAD/OPTIONS: read-only, don't create session.
// POST/PUT/DELETE: create session if needed.
func sessionMiddleware(sm *sessionManager, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				sessionID, err := sm.ID(r)
				if err == nil {
					ctx := context.WithValue(r.Context(), ctxKeySessionID, sessionID)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				// No session — pre-session state, continue without session ID
				next.ServeHTTP(w, r)
				return
			}

			// State-changing request: create session if needed
			sessionID, err := sm.GetOrCreate(w, r)
			if err != nil {
				logger.Error("session creation failed",
					"error", err,
					"path", r.URL.Path,
					"method", r.Method,
					"remote_addr", r.RemoteAddr,
				)
				WriteError(w, http.StatusInternalServerError, "session_error", "session creation failed")
				return
			}

			ctx := context.WithValue(r.Context(), ctxKeySessionID, sessionID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// csrfMiddleware validates CSRF tokens for state-changing requests.
// Reads token from X-CSRF-Token header (JSON API pattern).
// Supports both pre-session and session-bound tokens.
func csrfMiddleware(sm *sessionManager, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CSRF for safe methods
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			csrfToken := r.Header.Get("X-CSRF-Token")

			// Check pre-session token
			if isPreSessionToken(csrfToken) {
				if err := sm.CheckPreSessionCSRF(csrfToken); err != nil {
					logger.Warn("pre-session CSRF validation failed",
						"error", err,
						"path", r.URL.Path,
						"method", r.Method,
					)
					WriteError(w, http.StatusForbidden, "csrf_invalid", "CSRF validation failed")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Session-bound token
			sessionID, ok := SessionIDFromContext(r.Context())
			if !ok {
				logger.Error("CSRF validation failed: session ID not in context",
					"path", r.URL.Path,
					"method", r.Method,
				)
				WriteError(w, http.StatusForbidden, "session_required", "session required")
				return
			}

			if err := sm.CheckCSRF(sessionID, csrfToken); err != nil {
				logger.Warn("CSRF validation failed",
					"error", err,
					"session", sessionID,
					"path", r.URL.Path,
					"method", r.Method,
				)
				WriteError(w, http.StatusForbidden, "csrf_invalid", "CSRF validation failed")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// setSecurityHeaders applies common security headers for API responses.
// HSTS is only set when not in dev mode (requires HTTPS).
func setSecurityHeaders(w http.ResponseWriter, isDev bool) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	if !isDev {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
}

// isPreSessionToken checks if a CSRF token is a pre-session token.
func isPreSessionToken(token string) bool {
	return strings.HasPrefix(token, preSessionPrefix)
}

// ============================================================================
// Rate Limiting
// ============================================================================

const (
	rateLimiterCleanupInterval = 5 * time.Minute
	rateLimiterStaleThreshold  = 10 * time.Minute
)

// rateLimiter implements per-IP token bucket rate limiting.
// Cleanup of stale entries happens inline during allow() calls.
type rateLimiter struct {
	mu          sync.Mutex
	visitors    map[string]*visitor
	rate        float64 // tokens per second
	burst       int     // max tokens (also initial tokens)
	lastCleanup time.Time
}

// visitor tracks the token bucket state for a single IP.
type visitor struct {
	tokens   float64
	lastSeen time.Time
}

// newRateLimiter creates a rate limiter.
// rate: tokens refilled per second. burst: maximum tokens (and initial allowance).
func newRateLimiter(rate float64, burst int) *rateLimiter {
	return &rateLimiter{
		visitors:    make(map[string]*visitor),
		rate:        rate,
		burst:       burst,
		lastCleanup: time.Now(),
	}
}

// allow checks if a request from the given IP is allowed.
// Returns false if the IP has exhausted its tokens.
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Periodic cleanup of stale entries
	if now.Sub(rl.lastCleanup) > rateLimiterCleanupInterval {
		for k, v := range rl.visitors {
			if now.Sub(v.lastSeen) > rateLimiterStaleThreshold {
				delete(rl.visitors, k)
			}
		}
		rl.lastCleanup = now
	}

	v, exists := rl.visitors[ip]
	if !exists {
		rl.visitors[ip] = &visitor{
			tokens:   float64(rl.burst) - 1,
			lastSeen: now,
		}
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(v.lastSeen).Seconds()
	v.tokens += elapsed * rl.rate
	if v.tokens > float64(rl.burst) {
		v.tokens = float64(rl.burst)
	}
	v.lastSeen = now

	if v.tokens < 1 {
		return false
	}

	v.tokens--
	return true
}

// rateLimitMiddleware returns middleware that limits requests per IP.
// Uses token bucket algorithm: each IP gets `burst` initial tokens,
// refilling at `rate` tokens per second.
func rateLimitMiddleware(rl *rateLimiter, trustProxy bool, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r, trustProxy)
			if !rl.allow(ip) {
				logger.Warn("rate limit exceeded",
					"ip", ip,
					"path", r.URL.Path,
					"method", r.Method,
				)
				w.Header().Set("Retry-After", "1")
				WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the client IP from the request.
//
// When trustProxy is true, checks X-Real-IP first (set by nginx/HAProxy),
// then X-Forwarded-For (first IP). Header values are validated with net.ParseIP
// to prevent injection of non-IP strings into rate limiter keys.
//
// When trustProxy is false, only uses RemoteAddr (safe default for direct exposure).
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		// Prefer X-Real-IP (single value, set by reverse proxy)
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
				return ip.String()
			}
		}

		// Fall back to X-Forwarded-For (first IP is the client)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			raw := xff
			if first, _, ok := strings.Cut(xff, ","); ok {
				raw = first
			}
			if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
				return ip.String()
			}
		}
	}

	// Fall back to RemoteAddr (strip port)
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
