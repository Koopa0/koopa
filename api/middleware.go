package api

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/koopa0/koopa-cli/internal/log"
)

// APIKeyEnvVar is the environment variable name for the API key.
// When set, all non-health check endpoints require this key for authentication.
const APIKeyEnvVar = "KOOPA_API_KEY" // #nosec G101 -- This is a constant name, not a credential

// APIKeyHeader is the HTTP header name for API key authentication.
const APIKeyHeader = "X-API-Key" // #nosec G101 -- This is a constant name, not a credential

// BearerPrefix is the prefix for Bearer token authentication.
const BearerPrefix = "Bearer "

// statusRecorder wraps http.ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader captures the status code and writes it to the underlying ResponseWriter.
func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Write writes data and ensures status is set to 200 if WriteHeader wasn't called.
// This handles the case where Write() is called without explicit WriteHeader().
func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// loggingMiddleware returns a middleware that logs all HTTP requests with method, path, status, and duration.
func loggingMiddleware(logger log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			logger.Debug("http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration", time.Since(start))
		})
	}
}

// recoveryMiddleware returns a middleware that recovers from panics and returns 500 Internal Server Error.
func recoveryMiddleware(logger log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error("panic recovered", "error", err, "path", r.URL.Path)
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// chain applies middleware in order: first middleware wraps outermost.
func chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// authMiddleware returns a middleware that validates API key authentication.
// Authentication is REQUIRED when KOOPA_API_KEY environment variable is set.
// When KOOPA_API_KEY is not set, authentication is skipped (development mode).
//
// Supported authentication methods:
//   - X-API-Key header: X-API-Key: <api-key>
//   - Authorization header: Authorization: Bearer <api-key>
//
// Health check endpoints (/health, /ready) are always exempt from authentication.
func authMiddleware(logger log.Logger) func(http.Handler) http.Handler {
	apiKey := os.Getenv(APIKeyEnvVar)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip authentication if API key is not configured (development mode)
			if apiKey == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Skip authentication for health check endpoints
			if isHealthCheckEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Extract API key from request
			providedKey := extractAPIKey(r)
			if providedKey == "" {
				logger.Warn("missing API key",
					"path", r.URL.Path,
					"remote_addr", r.RemoteAddr)
				http.Error(w, "Unauthorized: API key required", http.StatusUnauthorized)
				return
			}

			// Constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(providedKey), []byte(apiKey)) != 1 {
				logger.Warn("invalid API key",
					"path", r.URL.Path,
					"remote_addr", r.RemoteAddr)
				http.Error(w, "Unauthorized: invalid API key", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractAPIKey extracts the API key from request headers.
// Supports both X-API-Key header and Authorization Bearer token.
func extractAPIKey(r *http.Request) string {
	// Check X-API-Key header first
	if key := r.Header.Get(APIKeyHeader); key != "" {
		return key
	}

	// Check Authorization header (Bearer token)
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, BearerPrefix) {
		return strings.TrimPrefix(auth, BearerPrefix)
	}

	return ""
}

// isHealthCheckEndpoint returns true if the path is a health check endpoint.
// Health check endpoints are exempt from authentication for k8s probes.
func isHealthCheckEndpoint(path string) bool {
	return path == "/health" || path == "/ready" ||
		path == "/health/live" || path == "/health/ready"
}
