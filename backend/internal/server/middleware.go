package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// requestIDKey is the context key for the per-request correlation ID.
type requestIDKey struct{}

// RequestIDFrom extracts the request ID from the context, or empty string.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// requestIDMiddleware generates or reads a unique ID for each request,
// sets it in the context and response header, and enriches the logger.
func requestIDMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-ID")
			if id == "" {
				// Prefer Cloudflare Ray ID if behind tunnel.
				id = r.Header.Get("CF-Ray")
			}
			if id == "" {
				id = uuid.New().String()
			}
			w.Header().Set("X-Request-ID", id)
			ctx := context.WithValue(r.Context(), requestIDKey{}, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func loggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration", time.Since(start),
				"request_id", RequestIDFrom(r.Context()),
			)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap returns the underlying ResponseWriter, enabling
// http.ResponseController to access Flusher, Hijacker, etc.
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func corsMiddleware(origin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.Header().Add("Vary", "Origin")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// ipEntry holds a rate limiter and the time it was last used.
type ipEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// defaultMaxEntries is the maximum number of IPs tracked before eviction
// is forced. Prevents OOM under DDoS with many unique source IPs.
const defaultMaxEntries = 10_000

// ipRateLimiter tracks per-IP rate limiters.
type ipRateLimiter struct {
	mu         sync.Mutex
	entries    map[string]*ipEntry
	rate       rate.Limit
	burst      int
	maxEntries int
	logger     *slog.Logger
}

func newIPRateLimiter(r rate.Limit, burst int, logger *slog.Logger) *ipRateLimiter {
	return &ipRateLimiter{
		entries:    make(map[string]*ipEntry),
		rate:       r,
		burst:      burst,
		maxEntries: defaultMaxEntries,
		logger:     logger,
	}
}

func (l *ipRateLimiter) limiter(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	if e, ok := l.entries[ip]; ok {
		e.lastSeen = time.Now()
		return e.limiter
	}

	// New IP — enforce the size cap before inserting.
	if len(l.entries) >= l.maxEntries {
		l.evictOldestLocked()
	}
	if len(l.entries) >= l.maxEntries {
		// All entries are fresh; return a temporary limiter without storing.
		l.logger.Warn("rate limiter map at capacity, using ephemeral limiter",
			"ip", ip, "entries", len(l.entries), "max", l.maxEntries)
		return rate.NewLimiter(l.rate, l.burst)
	}

	e := &ipEntry{limiter: rate.NewLimiter(l.rate, l.burst), lastSeen: time.Now()}
	l.entries[ip] = e
	return e.limiter
}

// evictOldestLocked removes the least-recently-seen entries to free at least
// 10% of capacity (minimum 1 entry). The caller MUST hold l.mu.
func (l *ipRateLimiter) evictOldestLocked() {
	evictCount := max(l.maxEntries/10, 1)
	target := l.maxEntries - evictCount

	for len(l.entries) > target {
		oldestIP := ""
		oldestTime := time.Now()
		for ip, e := range l.entries {
			if e.lastSeen.Before(oldestTime) {
				oldestIP = ip
				oldestTime = e.lastSeen
			}
		}
		if oldestIP == "" {
			break
		}
		delete(l.entries, oldestIP)
	}
}

// evictStale removes entries that have not been seen for the given duration.
func (l *ipRateLimiter) evictStale(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, e := range l.entries {
		if e.lastSeen.Before(cutoff) {
			delete(l.entries, ip)
		}
	}
}

// rateLimitMiddleware returns a per-IP rate limiter for specific routes.
// 10 requests per minute per IP, burst of 10.
// The done channel stops the background cleanup goroutine on server shutdown.
func rateLimitMiddleware(logger *slog.Logger, done <-chan struct{}) func(http.Handler) http.Handler {
	lim := newIPRateLimiter(rate.Every(6*time.Second), 10, logger)

	// Evict IPs not seen for 10+ minutes, check every 5 minutes.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				lim.evictStale(10 * time.Minute)
			}
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Prefer CF-Connecting-IP (set by Cloudflare Tunnel, cannot be spoofed).
			// Fall back to X-Forwarded-For (set by BFF proxy), then RemoteAddr.
			ip := r.RemoteAddr
			if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
				ip = cfIP
			} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				if idx := strings.Index(xff, ","); idx != -1 {
					ip = strings.TrimSpace(xff[:idx])
				} else {
					ip = strings.TrimSpace(xff)
				}
			}
			// Strip port from RemoteAddr ("192.168.1.1:12345" → "192.168.1.1")
			// so rate limiting keys on IP, not on connection.
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}
			if !lim.limiter(ip).Allow() {
				logger.Warn("rate limit exceeded", "ip", ip, "path", r.URL.Path)
				http.Error(w, `{"error":{"code":"RATE_LIMITED","message":"too many requests"}}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// csrfMiddleware returns a handler that applies Fetch metadata CSRF protection.
// It uses Go 1.25+ http.CrossOriginProtection to reject cross-origin mutating
// browser requests. Non-browser requests (no Sec-Fetch-Site header) are allowed,
// which permits server-to-server calls from the BFF proxy.
func csrfMiddleware(corsOrigin string, logger *slog.Logger) (func(http.Handler) http.Handler, error) {
	cop := http.NewCrossOriginProtection()
	if corsOrigin != "" {
		if err := cop.AddTrustedOrigin(corsOrigin); err != nil {
			return nil, fmt.Errorf("csrf: adding trusted origin %q: %w", corsOrigin, err)
		}
	}

	// Webhooks are server-to-server and carry HMAC signatures, not browser cookies.
	// Bypass CSRF checks so they are not rejected when an Origin header is present.
	// List specific routes rather than a wildcard to avoid covering future endpoints.
	// Note: /api/webhook/obsidian uses authMid (JWT) so it does not need a bypass.
	cop.AddInsecureBypassPattern("POST /api/webhook/github")
	cop.AddInsecureBypassPattern("POST /api/webhook/notion")

	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Warn("csrf: blocked cross-origin request",
			"method", r.Method,
			"path", r.URL.Path,
			"origin", r.Header.Get("Origin"),
			"sec-fetch-site", r.Header.Get("Sec-Fetch-Site"),
		)
		http.Error(w, `{"error":{"code":"FORBIDDEN","message":"cross-origin request blocked"}}`, http.StatusForbidden)
	}))

	return func(next http.Handler) http.Handler {
		return cop.Handler(next)
	}, nil
}
