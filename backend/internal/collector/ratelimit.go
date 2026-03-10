package collector

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// DomainLimiter provides per-domain rate limiting.
type DomainLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	interval time.Duration
}

// NewDomainLimiter returns a DomainLimiter with the given per-domain interval.
func NewDomainLimiter(interval time.Duration) *DomainLimiter {
	return &DomainLimiter{
		limiters: make(map[string]*rate.Limiter),
		interval: interval,
	}
}

// Wait blocks until the rate limit for the given URL's domain allows a request.
func (d *DomainLimiter) Wait(ctx context.Context, rawURL string) error {
	domain := domainFromURL(rawURL)
	d.mu.Lock()
	lim, ok := d.limiters[domain]
	if !ok {
		lim = rate.NewLimiter(rate.Every(d.interval), 1)
		d.limiters[domain] = lim
	}
	d.mu.Unlock()
	return lim.Wait(ctx)
}

// domainFromURL extracts the lowercase host from a URL.
func domainFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return strings.ToLower(u.Host)
}
