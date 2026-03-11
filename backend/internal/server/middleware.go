package server

import (
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

// ipRateLimiter tracks per-IP rate limiters.
type ipRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
}

func newIPRateLimiter(r rate.Limit, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    burst,
	}
}

func (l *ipRateLimiter) limiter(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.limiters[ip]
	if !ok {
		lim = rate.NewLimiter(l.rate, l.burst)
		l.limiters[ip] = lim
	}
	return lim
}

// rateLimitMiddleware returns a per-IP rate limiter for specific routes.
// 10 requests per minute per IP, burst of 10.
func rateLimitMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	lim := newIPRateLimiter(rate.Every(6*time.Second), 10)

	// Clean up stale entries every 10 minutes.
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			lim.mu.Lock()
			clear(lim.limiters)
			lim.mu.Unlock()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
				ip = fwd
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
func csrfMiddleware(corsOrigin string, logger *slog.Logger) func(http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	if corsOrigin != "" {
		if err := cop.AddTrustedOrigin(corsOrigin); err != nil {
			logger.Error("csrf: adding trusted origin", "origin", corsOrigin, "error", err)
		}
	}

	// Webhooks are server-to-server and carry HMAC signatures, not browser cookies.
	// Bypass CSRF checks so they are not rejected when an Origin header is present.
	cop.AddInsecureBypassPattern("POST /api/webhook/{path...}")

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
	}
}
