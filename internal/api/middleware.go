package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Context key types (unexported to prevent collisions).
type sessionIDKey struct{}
type userIDCtxKey struct{}

var ctxKeySessionID = sessionIDKey{}
var ctxKeyUserID = userIDCtxKey{}

// sessionIDFromContext retrieves the active session ID from the request context.
// Returns uuid.Nil and false if not found.
func sessionIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	sessionID, ok := ctx.Value(ctxKeySessionID).(uuid.UUID)
	return sessionID, ok
}

// userIDFromContext retrieves the user identity from the request context.
// Returns empty string and false if not found.
func userIDFromContext(ctx context.Context) (string, bool) {
	uid, ok := ctx.Value(ctxKeyUserID).(string)
	return uid, ok
}

// loggingWriter wraps http.ResponseWriter to capture metrics.
// Implements Flusher for SSE streaming and Unwrap for ResponseController.
type loggingWriter struct {
	w            http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (lw *loggingWriter) Header() http.Header {
	return lw.w.Header()
}

func (lw *loggingWriter) WriteHeader(code int) {
	lw.statusCode = code
	lw.w.WriteHeader(code)
}

//nolint:wrapcheck // http.ResponseWriter wrapper must return unwrapped errors
func (lw *loggingWriter) Write(b []byte) (int, error) {
	if lw.statusCode == 0 {
		lw.statusCode = http.StatusOK
	}
	n, err := lw.w.Write(b)
	lw.bytesWritten += int64(n)
	return n, err
}

// Flush implements http.Flusher for SSE streaming support.
func (lw *loggingWriter) Flush() {
	if f, ok := lw.w.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter for http.ResponseController.
func (lw *loggingWriter) Unwrap() http.ResponseWriter {
	return lw.w
}

// recoveryMiddleware recovers from panics to prevent server crashes.
func recoveryMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrapper := &loggingWriter{w: w}

			defer func() {
				if err := recover(); err != nil {
					logger.Error("panic recovered",
						"error", err,
						"path", r.URL.Path,
						"headers_sent", wrapper.statusCode != 0,
					)

					if wrapper.statusCode == 0 {
						WriteError(w, http.StatusInternalServerError, "internal_error", "internal server error", logger)
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
// Reuses an existing *loggingWriter from outer middleware (e.g., recoveryMiddleware)
// to avoid double-wrapping the ResponseWriter.
func loggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			wrapper, ok := w.(*loggingWriter)
			if !ok {
				wrapper = &loggingWriter{w: w}
			}

			next.ServeHTTP(wrapper, r)

			status := wrapper.statusCode
			if status == 0 {
				status = http.StatusOK
			}

			logger.Debug("http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", status,
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

// userMiddleware auto-provisions and extracts user identity (uid cookie).
// On first visit, generates a new UUID and sets the uid cookie.
// Subsequent requests use the existing uid cookie value.
func userMiddleware(sm *sessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := sm.UserID(r)
			if userID == "" {
				userID = uuid.New().String()
				sm.setUserCookie(w, userID)
			}
			ctx := context.WithValue(r.Context(), ctxKeyUserID, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// sessionMiddleware extracts the active session ID from the sid cookie and adds
// it to the request context. If no valid session cookie is present, the request
// continues without a session ID in context.
func sessionMiddleware(sm *sessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionID, err := sm.SessionID(r)
			if err == nil {
				ctx := context.WithValue(r.Context(), ctxKeySessionID, sessionID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// No valid session cookie — continue without session in context
			next.ServeHTTP(w, r)
		})
	}
}

// csrfMiddleware validates CSRF tokens for state-changing requests.
// Reads token from X-CSRF-Token header (JSON API pattern).
// Supports both pre-session and user-bound tokens.
func csrfMiddleware(sm *sessionManager, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CSRF for safe methods
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			csrfToken := r.Header.Get("X-CSRF-Token")

			// Check pre-session token (before uid cookie is established)
			if isPreSessionToken(csrfToken) {
				if err := sm.CheckPreSessionCSRF(csrfToken); err != nil {
					logger.Warn("pre-session CSRF validation failed",
						"error", err,
						"path", r.URL.Path,
						"method", r.Method,
					)
					WriteError(w, http.StatusForbidden, "csrf_invalid", "CSRF validation failed", logger)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// User-bound token
			userID, ok := userIDFromContext(r.Context())
			if !ok || userID == "" {
				logger.Error("validating CSRF: user ID not in context",
					"path", r.URL.Path,
					"method", r.Method,
				)
				WriteError(w, http.StatusForbidden, "user_required", "user identity required", logger)
				return
			}

			if err := sm.CheckCSRF(userID, csrfToken); err != nil {
				logger.Warn("validating CSRF",
					"error", err,
					"user", userID,
					"path", r.URL.Path,
					"method", r.Method,
				)
				WriteError(w, http.StatusForbidden, "csrf_invalid", "CSRF validation failed", logger)
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
