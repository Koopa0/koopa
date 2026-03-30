package server

import (
	"log/slog"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/time/rate"
)

// TestIPRateLimiter_EvictStale_BackgroundGoroutine_Synctest verifies that the
// background goroutine in rateLimitMiddleware runs evictStale at 5-minute
// intervals. We use a standalone ipRateLimiter (not through the middleware) to
// control the eviction call directly, and a separate goroutine that mirrors the
// production ticker logic. This tests the timing of the ticker, not the HTTP
// layer.
func TestIPRateLimiter_EvictStale_BackgroundGoroutine_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lim := newIPRateLimiter(rate.Every(time.Second), 5, slog.New(slog.DiscardHandler))
		lim.maxEntries = 100

		done := make(chan struct{})
		defer close(done)

		// Mirror the production eviction goroutine from rateLimitMiddleware.
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

		// Insert a stale entry directly (10+ minutes old).
		lim.mu.Lock()
		lim.entries["stale-ip"] = &ipEntry{
			limiter:  rate.NewLimiter(lim.rate, lim.burst),
			lastSeen: time.Now().Add(-15 * time.Minute),
		}
		lim.mu.Unlock()

		// Insert a fresh entry.
		_ = lim.limiter("fresh-ip")

		// Let goroutines settle before advancing time.
		synctest.Wait()

		// Advance past one 5-minute eviction tick.
		time.Sleep(5*time.Minute + time.Second)
		synctest.Wait()

		lim.mu.Lock()
		_, stalePresent := lim.entries["stale-ip"]
		_, freshPresent := lim.entries["fresh-ip"]
		lim.mu.Unlock()

		if stalePresent {
			t.Error("stale-ip still present after eviction tick, want evicted")
		}
		if !freshPresent {
			t.Error("fresh-ip missing after eviction tick, want present")
		}
	})
}

// TestIPRateLimiter_RateRecovery_Synctest verifies that after exhausting the
// burst tokens, advancing virtual time allows new requests through. This tests
// the golang.org/x/time/rate.Limiter's token replenishment with fake time.
func TestIPRateLimiter_RateRecovery_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// 1 token per 2 seconds, burst of 1.
		lim := newIPRateLimiter(rate.Every(2*time.Second), 1, slog.New(slog.DiscardHandler))
		lim.maxEntries = 100

		const ip = "10.0.0.1"

		// First request should succeed (burst=1 token available).
		if !lim.limiter(ip).Allow() {
			t.Fatal("first Allow() = false, want true (burst token available)")
		}

		// Immediately after, no tokens remain.
		if lim.limiter(ip).Allow() {
			t.Fatal("second Allow() = true immediately after exhausting burst, want false")
		}

		// Advance virtual time past the refill period.
		time.Sleep(2*time.Second + time.Millisecond)
		synctest.Wait()

		// Token should be refilled now.
		if !lim.limiter(ip).Allow() {
			t.Error("Allow() after 2s refill = false, want true")
		}
	})
}

// TestIPRateLimiter_EvictStale_ThenNewEntry_Synctest verifies the end-to-end
// flow: an entry is directly marked stale, the background goroutine evicts it,
// and subsequent access creates a fresh entry with a full burst.
func TestIPRateLimiter_EvictStale_ThenNewEntry_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Use a tight rate so we can exhaust and recover.
		lim := newIPRateLimiter(rate.Every(time.Hour), 1, slog.New(slog.DiscardHandler))
		lim.maxEntries = 100

		done := make(chan struct{})
		defer close(done)

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

		const ip = "10.1.2.3"

		// Insert an entry through the normal path.
		_ = lim.limiter(ip)

		// Exhaust the burst of the returned limiter.
		lim.mu.Lock()
		entry := lim.entries[ip]
		lim.mu.Unlock()

		if !entry.limiter.Allow() {
			t.Fatal("first Allow() = false, want true (burst token)")
		}
		if entry.limiter.Allow() {
			t.Fatal("second Allow() = true immediately, want false (burst exhausted)")
		}

		// Backdate lastSeen so the entry is clearly stale when the next tick fires.
		// Move lastSeen to 15 minutes ago so that at the t=5min tick the cutoff
		// (t=5min - 10min = t=-5min) does not reach it, but at t=16min the cutoff
		// (t=16min - 10min = t=6min) is after the backdated lastSeen (t=-15min equivalent).
		// Simpler: set lastSeen to a time that is definitely > 10 minutes before any tick.
		// Under synctest, time starts at some epoch; we set lastSeen = now - 20 min.
		lim.mu.Lock()
		lim.entries[ip].lastSeen = time.Now().Add(-20 * time.Minute)
		lim.mu.Unlock()

		synctest.Wait()

		// Advance past one 5-minute tick. Cutoff = now+5min - 10min = now-5min.
		// lastSeen = now-20min, which is before now-5min → entry is evicted.
		time.Sleep(5*time.Minute + time.Second)
		synctest.Wait()

		lim.mu.Lock()
		_, present := lim.entries[ip]
		lim.mu.Unlock()

		if present {
			t.Fatal("entry should be evicted after stale eviction tick, still present")
		}

		// A new call to limiter() must insert a fresh entry with a full burst token.
		freshLimiter := lim.limiter(ip)
		if !freshLimiter.Allow() {
			t.Error("Allow() on fresh limiter after re-insert = false, want true")
		}
	})
}

// TestRateLimitMiddleware_BackgroundGoroutineExits_Synctest verifies that the
// background goroutine inside rateLimitMiddleware exits when the done channel
// is closed. We confirm this by checking that synctest.Wait() returns cleanly
// after closing done — meaning no goroutine is still running inside the bubble.
func TestRateLimitMiddleware_BackgroundGoroutineExits_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})

		// Create middleware — this starts the background goroutine.
		_ = rateLimitMiddleware(slog.New(slog.DiscardHandler), done)

		// Let the goroutine start and block on select.
		synctest.Wait()

		// Close done to signal shutdown.
		close(done)

		// synctest.Wait() will return only when all goroutines in the bubble
		// have blocked or exited. If the goroutine exits on done, Wait returns
		// promptly. If it leaks, the test framework will report a goroutine leak.
		synctest.Wait()
	})
}
