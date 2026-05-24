// middleware.go holds the app server's general-purpose HTTP middleware
// (request ID, recovery, logging, CORS, security headers) and the chain
// composer that assembles them.
//
// Feature-specific middleware lives with its feature:
//   - JWT auth              — internal/auth
//   - Per-request actor tx  — internal/api (ActorMiddleware)
//
// Ordering (outermost first, set by registerRoutes in routes.go):
//
//	recovery → requestID → cors → logging → securityHeaders → mux
//
// recovery is outermost so panics anywhere downstream become a 500;
// requestID is set before logging so every request log carries an id;
// cors must sit before auth middleware (added per-route) so preflight
// never hits the auth check.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// requestIDKey is the unexported context key for the request ID.
// Per .claude/rules/concurrency.md, context keys are unexported empty
// struct types — never strings or ints.
type requestIDKey struct{}

// requestID generates a unique request ID and stores it in the context.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := generateID()
		ctx := context.WithValue(r.Context(), requestIDKey{}, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func generateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// recovery catches panics and returns 500.
func recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error("panic recovered",
						"panic", rec,
						"method", r.Method,
						"path", r.URL.Path,
					)
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// statusRecorder captures the status code written to the response.
// Implements Unwrap() so http.Flusher and other optional interfaces
// are still accessible through the wrapped ResponseWriter.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.code = code
	sr.ResponseWriter.WriteHeader(code)
}

// Unwrap returns the underlying ResponseWriter, enabling Go 1.20+
// response writer interface discovery (http.Flusher, http.Hijacker, etc.).
func (sr *statusRecorder) Unwrap() http.ResponseWriter {
	return sr.ResponseWriter
}

// logging logs each request with method, path, status, and duration.
// Skips the /metrics scrape path because Prometheus polls it every 15s
// and the resulting log spam drowns out real request logs in Loki.
func logging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			sr := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
			next.ServeHTTP(sr, r)

			rid, _ := r.Context().Value(requestIDKey{}).(string)
			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sr.code,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", rid,
			)
		})
	}
}

// cors handles CORS preflight and sets headers for cross-origin requests.
func cors(origin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "86400")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// securityHeaders adds standard security response headers.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// chain composes middleware in order: first applied is outermost.
func chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// httpMetrics wraps an http.Handler with OTel histogram + counter
// recording. The observation runs in a deferred function so a panicking
// inner handler still produces a data point: the outer recovery
// middleware catches the panic AFTER our defer fires.
//
// Labels (identical on both instruments — co-aggregation must work):
//   - method: raw HTTP method (e.g. "GET")
//   - route:  r.Pattern (the matched ServeMux template, e.g.
//     "GET /api/contents/{slug}"). Falls back to "unknown" when no
//     pattern matched (404s).
//   - status: raw 3-digit status code as a string (e.g. "200", "500").
//     NOT quantized — existing Grafana alerts use status=~"5.." regex
//     which matches raw codes only.
//
// Wiring contract: this middleware MUST sit between the ServeMux and the
// final handler (i.e. the ServeMux dispatches into it) so r.Pattern is
// populated by the time our defer fires. In Go 1.22+ ServeMux mutates
// r.Pattern in place on the original request pointer, so a single wrap
// around the mux works — no per-route wiring change required.
func httpMetrics(meter metric.Meter) (func(http.Handler) http.Handler, error) {
	duration, err := meter.Float64Histogram(
		"http.server.request.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of HTTP server requests"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating duration histogram: %w", err)
	}
	requests, err := meter.Int64Counter(
		"http.requests",
		metric.WithDescription("Count of HTTP server requests"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating requests counter: %w", err)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip noisy infrastructure routes: /metrics is scraped every
			// 15s, /healthz and /readyz get hit by external uptime checks.
			// Instrumenting them would flood the aggregation with traffic
			// that tells us nothing about user-facing latency.
			switch r.URL.Path {
			case "/metrics", "/healthz", "/readyz":
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			sr := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
			defer func() {
				// On panic, the inner handler may not have reached
				// WriteHeader so sr.code is still 200. Stamp 500 here so
				// the metric reflects what the outer recovery middleware
				// will write to the client. Without this, status="200"
				// is recorded for panicked requests and alerts on
				// status=~"5.." silently miss panic storms.
				rec := recover()
				if rec != nil {
					sr.code = http.StatusInternalServerError
				}
				route := r.Pattern
				if route == "" {
					route = "unknown"
				}
				attrs := metric.WithAttributes(
					attribute.String("method", r.Method),
					attribute.String("route", route),
					attribute.String("status", strconv.Itoa(sr.code)),
				)
				duration.Record(r.Context(), time.Since(start).Seconds(), attrs)
				requests.Add(r.Context(), 1, attrs)
				if rec != nil {
					panic(rec)
				}
			}()
			next.ServeHTTP(sr, r)
		})
	}, nil
}
