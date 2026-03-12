package webhook

import (
	"fmt"
	"sync"
	"time"
)

// DeduplicationCache tracks seen webhook delivery IDs to prevent replay attacks.
// Entries expire after the configured TTL, and a background goroutine cleans
// them up periodically.
type DeduplicationCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // delivery key → first seen time
	ttl     time.Duration
	done    chan struct{}
}

// NewDeduplicationCache returns a cache that expires entries after ttl.
// Call Stop to release the background cleanup goroutine.
func NewDeduplicationCache(ttl time.Duration) *DeduplicationCache {
	c := &DeduplicationCache{
		entries: make(map[string]time.Time),
		ttl:     ttl,
		done:    make(chan struct{}),
	}

	go c.cleanup()
	return c
}

// Seen returns true if the key was already seen within the TTL window.
// If not seen, records it and returns false.
func (c *DeduplicationCache) Seen(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.entries[key]; ok {
		return true
	}
	c.entries[key] = time.Now()
	return false
}

// Stop signals the cleanup goroutine to exit.
func (c *DeduplicationCache) Stop() {
	close(c.done)
}

// cleanup removes expired entries every ttl/2.
func (c *DeduplicationCache) cleanup() {
	interval := max(c.ttl/2, time.Second)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case now := <-ticker.C:
			c.mu.Lock()
			for k, seen := range c.entries {
				if now.Sub(seen) > c.ttl {
					delete(c.entries, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

// ValidateTimestamp checks that a webhook timestamp is within ±maxSkew of now.
// Returns an error if the timestamp is too old or too far in the future.
func ValidateTimestamp(timestamp string, maxSkew time.Duration) error {
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return fmt.Errorf("parsing timestamp %q: %w", timestamp, err)
	}
	diff := time.Since(t)
	if diff < 0 {
		diff = -diff
	}
	if diff > maxSkew {
		return fmt.Errorf("timestamp %q is %s from now, exceeds %s skew", timestamp, diff.Round(time.Second), maxSkew)
	}
	return nil
}
