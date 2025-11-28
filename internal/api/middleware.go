package api

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/koopa0/koopa-cli/internal/log"
)

// Constants for configuration and headers.
const (
	APIKeyEnvVar = "KOOPA_API_KEY" // #nosec G101
	APIKeyHeader = "X-API-Key"     // #nosec G101
	BearerPrefix = "Bearer "
)

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
func (w *loggingWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}

// Flush implements http.Flusher for SSE streaming support.
// This is critical for /api/chat/stream to work through the logging middleware.
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

// Middleware Generators

// LoggingMiddleware logs request details including latency, status, and response size.
func LoggingMiddleware(logger log.Logger) func(http.Handler) http.Handler {
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
func RecoveryMiddleware(logger log.Logger) func(http.Handler) http.Handler {
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

// AuthMiddleware enforces API key authentication.
func AuthMiddleware(logger log.Logger) func(http.Handler) http.Handler {
	apiKey := os.Getenv(APIKeyEnvVar)
	isDevMode := apiKey == ""

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isDevMode || isExemptPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			providedKey := extractAPIKey(r)
			if providedKey == "" {
				logger.Warn("authentication failed: missing key",
					"path", r.URL.Path,
					"ip", r.RemoteAddr,
				)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Constant-time comparison
			if subtle.ConstantTimeCompare([]byte(providedKey), []byte(apiKey)) != 1 {
				logger.Warn("authentication failed: invalid key",
					"path", r.URL.Path,
					"ip", r.RemoteAddr,
				)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Helper Functions

// Chain applies middlewares to a handler.
func Chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

func extractAPIKey(r *http.Request) string {
	if key := r.Header.Get(APIKeyHeader); key != "" {
		return key
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, BearerPrefix) {
		return strings.TrimPrefix(auth, BearerPrefix)
	}
	return ""
}

func isExemptPath(path string) bool {
	switch path {
	case "/health", "/ready", "/health/live", "/health/ready":
		return true
	default:
		return false
	}
}
