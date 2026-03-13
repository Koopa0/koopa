package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

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

// ipRateLimiter tracks per-IP rate limiters.
type ipRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*ipEntry
	rate    rate.Limit
	burst   int
}

func newIPRateLimiter(r rate.Limit, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		entries: make(map[string]*ipEntry),
		rate:    r,
		burst:   burst,
	}
}

func (l *ipRateLimiter) limiter(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok {
		e = &ipEntry{limiter: rate.NewLimiter(l.rate, l.burst)}
		l.entries[ip] = e
	}
	e.lastSeen = time.Now()
	return e.limiter
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
	lim := newIPRateLimiter(rate.Every(6*time.Second), 10)

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
			// Fall back to RemoteAddr for non-Tunnel requests (Docker internal).
			ip := r.RemoteAddr
			if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
				ip = cfIP
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
		http.Error(w, `{"error":{"code":"forbidden","message":"cross-origin request blocked"}}`, http.StatusForbidden)
	}))

	return func(next http.Handler) http.Handler {
		return cop.Handler(next)
	}, nil
}
