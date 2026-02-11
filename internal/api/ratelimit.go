package api

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	rateLimiterCleanupInterval = 5 * time.Minute
	rateLimiterStaleThreshold  = 10 * time.Minute
)

// rateLimiter implements per-IP rate limiting using golang.org/x/time/rate.
// Cleanup of stale entries happens inline during allow() calls.
type rateLimiter struct {
	mu          sync.Mutex
	visitors    map[string]*visitor
	limit       rate.Limit
	burst       int
	lastCleanup time.Time
}

// visitor holds a rate limiter and last-seen time for a single IP.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// newRateLimiter creates a rate limiter.
// r: tokens refilled per second. burst: maximum tokens (and initial allowance).
func newRateLimiter(r float64, burst int) *rateLimiter {
	return &rateLimiter{
		visitors:    make(map[string]*visitor),
		limit:       rate.Limit(r),
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
		limiter := rate.NewLimiter(rl.limit, rl.burst)
		rl.visitors[ip] = &visitor{
			limiter:  limiter,
			lastSeen: now,
		}
		limiter.Allow()
		return true
	}

	v.lastSeen = now
	return v.limiter.Allow()
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
				WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many requests", logger)
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
