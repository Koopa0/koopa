package web

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/koopa0/koopa/internal/web/handlers"
)

// Unexported context key type to prevent collisions (Critical Fix #2).
// Using a struct{} type instead of string prevents external packages
// from creating conflicting keys.
type sessionIDKey struct{}

var ctxKeySessionID = sessionIDKey{}

// GetSessionID retrieves the session ID from the request context.
// Returns uuid.Nil and false if not found.
func GetSessionID(ctx context.Context) (uuid.UUID, bool) {
	sessionID, ok := ctx.Value(ctxKeySessionID).(uuid.UUID)
	return sessionID, ok
}

// loggingWriter wraps http.ResponseWriter to capture metrics (status, size).
// It implements Flusher for SSE streaming support and Unwrap for ResponseController.
type loggingWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

// WriteHeader captures the status code.
func (w *loggingWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// Write captures the response size and defaults status to 200 if not set.
//
//nolint:wrapcheck // http.ResponseWriter wrapper must return unwrapped errors to maintain interface contract
func (w *loggingWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}

// Flush implements http.Flusher for SSE streaming support.
// This is critical for /genui/stream to work through the logging middleware.
func (w *loggingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter.
// This supports http.ResponseController for optional interface access.
func (w *loggingWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// LoggingMiddleware logs request details including latency, status, and response size.
func LoggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
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

// RecoveryMiddleware recovers from panics to prevent server crashes.
// It checks if headers have been sent before attempting to write an error response.
func RecoveryMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Wrap writer to track if headers have been sent
			wrapper := &loggingWriter{
				ResponseWriter: w,
				statusCode:     0, // 0 indicates headers not yet sent
			}

			defer func() {
				if err := recover(); err != nil {
					logger.Error("panic recovered",
						"error", err,
						"path", r.URL.Path,
						"headers_sent", wrapper.statusCode != 0,
					)

					// Only attempt to write error if headers haven't been sent
					if wrapper.statusCode == 0 {
						http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					} else {
						// Headers already sent, can only log
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

// RequireSession ensures a valid session exists before processing the request.
// GET requests use lazy session (read-only, don't create).
// POST/PUT/DELETE requests create session if needed for state-changing operations.
//
// Critical Fix #1: Uses *handlers.Sessions (HTTP session manager), NOT session.Store (database layer).
func RequireSession(sessions *handlers.Sessions, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// For GET/HEAD/OPTIONS: Try to read existing session, don't create
			// Lazy session creation - only create on first interaction
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				sessionID, err := sessions.ID(r)
				if err == nil {
					// Session exists - store in context
					ctx := context.WithValue(r.Context(), ctxKeySessionID, sessionID)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				// No session - continue without session ID (pre-session state)
				// Handler will provide pre-session CSRF token
				next.ServeHTTP(w, r)
				return
			}

			// For POST/PUT/DELETE: Create session if needed
			sessionID, err := sessions.GetOrCreate(w, r)
			if err != nil {
				logger.Error("session creation failed",
					"error", err,
					"path", r.URL.Path,
					"method", r.Method,
					"remote_addr", r.RemoteAddr,
				)
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			// Store session ID in context (using unexported key for security)
			ctx := context.WithValue(r.Context(), ctxKeySessionID, sessionID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// MethodOverride allows POST requests to override the HTTP method via _method form field.
// This enables progressive enhancement for HTML forms which only support GET and POST.
// Usage: <input type="hidden" name="_method" value="DELETE"/>
// Supported methods: PUT, PATCH, DELETE (all uppercase)
func MethodOverride(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Check form value (already parsed or parse now)
			if err := r.ParseForm(); err == nil {
				if override := r.FormValue("_method"); override != "" {
					// Only allow specific methods to prevent abuse
					switch override {
					case http.MethodPut, http.MethodPatch, http.MethodDelete:
						r.Method = override
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RequireCSRF validates CSRF tokens for state-changing requests (POST, PUT, DELETE).
// It skips validation for safe methods (GET, HEAD, OPTIONS).
// Supports both pre-session tokens (lazy session creation) and
// session-bound tokens. Pre-session tokens are validated without session ID.
func RequireCSRF(sessions *handlers.Sessions, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CSRF validation for safe methods
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			// Parse form to access csrf_token field
			if err := r.ParseForm(); err != nil {
				logger.Warn("CSRF validation failed: form parse error",
					"error", err,
					"path", r.URL.Path,
				)
				http.Error(w, "invalid form data", http.StatusBadRequest)
				return
			}

			csrfToken := r.FormValue("csrf_token")

			// Check if this is a pre-session token (lazy session creation)
			// Pre-session tokens are validated without session ID
			if handlers.IsPreSessionToken(csrfToken) {
				if err := sessions.CheckPreSessionCSRF(csrfToken); err != nil {
					logger.Warn("Pre-session CSRF validation failed",
						"error", err,
						"path", r.URL.Path,
						"method", r.Method,
					)
					http.Error(w, "CSRF validation failed", http.StatusForbidden)
					return
				}
				// Pre-session token valid - continue without session ID in context
				next.ServeHTTP(w, r)
				return
			}

			// Session-bound token: requires session ID in context
			sessionID, ok := GetSessionID(r.Context())
			if !ok {
				logger.Error("CSRF validation failed: session ID not in context",
					"path", r.URL.Path,
					"method", r.Method,
				)
				http.Error(w, "session required", http.StatusForbidden)
				return
			}

			if err := sessions.CheckCSRF(sessionID, csrfToken); err != nil {
				logger.Warn("CSRF validation failed",
					"error", err,
					"session", sessionID,
					"path", r.URL.Path,
					"method", r.Method,
				)
				http.Error(w, "CSRF validation failed", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
