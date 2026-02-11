package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter_AllowsWithinBurst(t *testing.T) {
	rl := newRateLimiter(1.0, 5)

	for i := range 5 {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("allow() returned false on request %d (within burst of 5)", i+1)
		}
	}
}

func TestRateLimiter_BlocksAfterBurst(t *testing.T) {
	rl := newRateLimiter(1.0, 3)

	// Exhaust the burst
	for range 3 {
		rl.allow("1.2.3.4")
	}

	if rl.allow("1.2.3.4") {
		t.Error("allow() should return false after burst exhausted")
	}
}

func TestRateLimiter_SeparateIPs(t *testing.T) {
	rl := newRateLimiter(1.0, 2)

	// Exhaust IP 1
	rl.allow("1.1.1.1")
	rl.allow("1.1.1.1")

	// IP 2 should still be allowed
	if !rl.allow("2.2.2.2") {
		t.Error("allow() should allow a different IP")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	rl := newRateLimiter(100.0, 1) // 100 tokens/sec so we can test quickly

	// Use the single token
	rl.allow("1.2.3.4")

	if rl.allow("1.2.3.4") {
		t.Error("allow() should be blocked immediately after burst exhausted")
	}

	// Wait enough time for a token to refill
	time.Sleep(20 * time.Millisecond)

	if !rl.allow("1.2.3.4") {
		t.Error("allow() should be allowed after token refill")
	}
}

func TestRateLimitMiddleware_Returns429(t *testing.T) {
	rl := newRateLimiter(0.001, 1) // Very low rate
	logger := discardLogger()

	handler := rateLimitMiddleware(rl, false, logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request should succeed
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want %d", w.Code, http.StatusOK)
	}

	// Second request should be rate limited
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited request status = %d, want %d", w.Code, http.StatusTooManyRequests)
	}

	if got := w.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want %q", got, "1")
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		trustProxy bool
		remoteAddr string
		xff        string
		xri        string
		want       string
	}{
		{
			name:       "remote addr with port",
			trustProxy: true,
			remoteAddr: "10.0.0.1:12345",
			want:       "10.0.0.1",
		},
		{
			name:       "X-Forwarded-For single when trusted",
			trustProxy: true,
			remoteAddr: "127.0.0.1:80",
			xff:        "203.0.113.50",
			want:       "203.0.113.50",
		},
		{
			name:       "X-Forwarded-For multiple when trusted",
			trustProxy: true,
			remoteAddr: "127.0.0.1:80",
			xff:        "203.0.113.50, 70.41.3.18, 150.172.238.178",
			want:       "203.0.113.50",
		},
		{
			name:       "X-Real-IP when trusted",
			trustProxy: true,
			remoteAddr: "127.0.0.1:80",
			xri:        "203.0.113.50",
			want:       "203.0.113.50",
		},
		{
			name:       "X-Real-IP takes precedence over X-Forwarded-For when trusted",
			trustProxy: true,
			remoteAddr: "127.0.0.1:80",
			xff:        "203.0.113.50",
			xri:        "198.51.100.1",
			want:       "198.51.100.1",
		},
		{
			name:       "untrusted ignores X-Forwarded-For",
			trustProxy: false,
			remoteAddr: "10.0.0.1:12345",
			xff:        "203.0.113.50",
			want:       "10.0.0.1",
		},
		{
			name:       "untrusted ignores X-Real-IP",
			trustProxy: false,
			remoteAddr: "10.0.0.1:12345",
			xri:        "203.0.113.50",
			want:       "10.0.0.1",
		},
		{
			name:       "invalid X-Real-IP falls through to XFF",
			trustProxy: true,
			remoteAddr: "127.0.0.1:80",
			xri:        "not-an-ip",
			xff:        "203.0.113.50",
			want:       "203.0.113.50",
		},
		{
			name:       "invalid XFF falls through to RemoteAddr",
			trustProxy: true,
			remoteAddr: "127.0.0.1:80",
			xff:        "not-an-ip",
			want:       "127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				r.Header.Set("X-Real-IP", tt.xri)
			}

			if got := clientIP(r, tt.trustProxy); got != tt.want {
				t.Errorf("clientIP(r, %v) = %q, want %q", tt.trustProxy, got, tt.want)
			}
		})
	}
}

func BenchmarkRateLimiterAllow(b *testing.B) {
	rl := newRateLimiter(1e9, 1<<30) // effectively unlimited
	for b.Loop() {
		rl.allow("1.2.3.4")
	}
}

func BenchmarkClientIP(b *testing.B) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Real-IP", "203.0.113.50")
	for b.Loop() {
		clientIP(r, true)
	}
}
