package collector

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// domainIdleTimeout is how long an unused domain limiter is kept before eviction.
const domainIdleTimeout = 30 * time.Minute

// domainEntry tracks a rate limiter and its last access time.
type domainEntry struct {
	limiter  *rate.Limiter
	lastUsed time.Time
}

// DomainLimiter provides per-domain rate limiting with idle eviction.
type DomainLimiter struct {
	mu       sync.Mutex
	limiters map[string]*domainEntry
	interval time.Duration
	done     chan struct{}
}

// NewDomainLimiter returns a DomainLimiter with the given per-domain interval.
// Call Stop to release the background cleanup goroutine.
func NewDomainLimiter(interval time.Duration) *DomainLimiter {
	d := &DomainLimiter{
		limiters: make(map[string]*domainEntry),
		interval: interval,
		done:     make(chan struct{}),
	}
	go d.cleanup()
	return d
}

// Stop releases the background cleanup goroutine.
func (d *DomainLimiter) Stop() {
	close(d.done)
}

// Wait blocks until the rate limit for the given URL's domain allows a request.
func (d *DomainLimiter) Wait(ctx context.Context, rawURL string) error {
	domain := domainFromURL(rawURL)
	d.mu.Lock()
	e, ok := d.limiters[domain]
	if !ok {
		e = &domainEntry{limiter: rate.NewLimiter(rate.Every(d.interval), 1)}
		d.limiters[domain] = e
	}
	e.lastUsed = time.Now()
	d.mu.Unlock()
	return e.limiter.Wait(ctx)
}

// cleanup periodically evicts domain limiters that have been idle longer than domainIdleTimeout.
func (d *DomainLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-d.done:
			return
		case now := <-ticker.C:
			d.mu.Lock()
			for domain, e := range d.limiters {
				if now.Sub(e.lastUsed) > domainIdleTimeout {
					delete(d.limiters, domain)
				}
			}
			d.mu.Unlock()
		}
	}
}

// domainFromURL extracts the lowercase host from a URL.
func domainFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return strings.ToLower(u.Host)
}
