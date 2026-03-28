package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/time/rate"
)

func TestStatusWriterUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, status: http.StatusOK}

	rc := http.NewResponseController(sw)
	if err := rc.Flush(); err != nil {
		t.Fatalf("Flush through ResponseController: %v", err)
	}
}

func TestIPRateLimiterMapSizeCap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		maxEntries  int
		insertCount int
		wantMaxSize int
	}{
		{
			name:        "below cap",
			maxEntries:  10,
			insertCount: 5,
			wantMaxSize: 5,
		},
		{
			name:        "at cap triggers eviction",
			maxEntries:  10,
			insertCount: 15,
			wantMaxSize: 10,
		},
		{
			name:        "far beyond cap stays bounded",
			maxEntries:  5,
			insertCount: 100,
			wantMaxSize: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lim := newIPRateLimiter(rate.Every(time.Second), 1, slog.Default())
			lim.maxEntries = tt.maxEntries

			for i := range tt.insertCount {
				ip := fmt.Sprintf("10.0.0.%d", i)
				got := lim.limiter(ip)
				if got == nil {
					t.Fatalf("limiter(%q) returned nil", ip)
				}
			}

			lim.mu.Lock()
			size := len(lim.entries)
			lim.mu.Unlock()

			if size > tt.wantMaxSize {
				t.Errorf("map size = %d, want <= %d", size, tt.wantMaxSize)
			}
		})
	}
}

func TestIPRateLimiterEphemeralLimiter(t *testing.T) {
	t.Parallel()

	// All entries have the same lastSeen (now), so eviction by oldest
	// cannot free enough space when all are equally fresh.
	// Use maxEntries=2 and fill both slots, then request a third IP.
	lim := newIPRateLimiter(rate.Limit(100), 100, slog.Default())
	lim.maxEntries = 2

	// Fill both slots with IPs that will be equally recent.
	_ = lim.limiter("10.0.0.1")
	_ = lim.limiter("10.0.0.2")

	// Third IP: eviction removes oldest (10.0.0.1), making room.
	got := lim.limiter("10.0.0.3")
	if got == nil {
		t.Fatal("limiter(10.0.0.3) returned nil")
	}

	// The limiter should still allow requests (not deny entirely).
	if !got.Allow() {
		t.Error("ephemeral/stored limiter should allow at least one request")
	}

	lim.mu.Lock()
	size := len(lim.entries)
	lim.mu.Unlock()

	if size > lim.maxEntries {
		t.Errorf("map size = %d, want <= %d", size, lim.maxEntries)
	}
}

func TestIPRateLimiterExistingIPNoEviction(t *testing.T) {
	t.Parallel()

	lim := newIPRateLimiter(rate.Every(time.Second), 5, slog.Default())
	lim.maxEntries = 3

	// Fill to capacity.
	_ = lim.limiter("10.0.0.1")
	_ = lim.limiter("10.0.0.2")
	_ = lim.limiter("10.0.0.3")

	// Re-accessing an existing IP should return the same limiter, not evict.
	before := lim.limiter("10.0.0.1")
	after := lim.limiter("10.0.0.1")

	if before != after {
		t.Error("limiter(existing IP) returned different limiter instance")
	}

	lim.mu.Lock()
	size := len(lim.entries)
	lim.mu.Unlock()

	if diff := cmp.Diff(3, size); diff != "" {
		t.Errorf("map size mismatch (-want +got):\n%s", diff)
	}
}

func TestIPRateLimiterConcurrentAccess(t *testing.T) {
	t.Parallel()

	lim := newIPRateLimiter(rate.Every(time.Second), 5, slog.Default())
	lim.maxEntries = 50

	const goroutines = 100
	var wg sync.WaitGroup
	for i := range goroutines {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		wg.Go(func() {
			got := lim.limiter(ip)
			if got == nil {
				t.Errorf("limiter(%q) returned nil", ip)
			}
		})
	}
	wg.Wait()

	lim.mu.Lock()
	size := len(lim.entries)
	lim.mu.Unlock()

	if size > lim.maxEntries {
		t.Errorf("map size = %d after concurrent access, want <= %d", size, lim.maxEntries)
	}
}

func TestIPRateLimiterEvictStaleReducesSize(t *testing.T) {
	t.Parallel()

	lim := newIPRateLimiter(rate.Every(time.Second), 5, slog.Default())
	lim.maxEntries = 10

	// Insert 5 entries with stale timestamps.
	lim.mu.Lock()
	staleTime := time.Now().Add(-20 * time.Minute)
	for i := range 5 {
		ip := fmt.Sprintf("10.0.0.%d", i)
		lim.entries[ip] = &ipEntry{
			limiter:  rate.NewLimiter(lim.rate, lim.burst),
			lastSeen: staleTime,
		}
	}
	lim.mu.Unlock()

	// Insert 5 fresh entries through normal path.
	for i := 5; i < 10; i++ {
		lim.limiter(fmt.Sprintf("10.0.0.%d", i))
	}

	// Evict entries older than 10 minutes.
	lim.evictStale(10 * time.Minute)

	lim.mu.Lock()
	size := len(lim.entries)
	lim.mu.Unlock()

	if diff := cmp.Diff(5, size); diff != "" {
		t.Errorf("map size after evictStale mismatch (-want +got):\n%s", diff)
	}
}
