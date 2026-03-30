package webhook

import (
	"testing"
	"testing/synctest"
	"time"
)

// TestDeduplicationCache_CleanupInterval_Synctest verifies that the cleanup
// goroutine runs at ttl/2 intervals. With a 4s TTL the cleanup interval is
// max(2s, 1s) = 2s. After one interval we expect stale entries from just before
// the TTL boundary to still be present; after two intervals (4s total) an entry
// inserted at t=0 that has aged past ttl is evicted.
func TestDeduplicationCache_CleanupInterval_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const ttl = 4 * time.Second
		// cleanup interval = max(ttl/2, 1s) = 2s

		c := NewDeduplicationCache(ttl)
		defer c.Stop()

		// Record key at virtual t=0.
		if c.Seen("interval-key") {
			t.Fatal("Seen(\"interval-key\") first call = true, want false")
		}

		// Advance past one cleanup interval (2s) but not past TTL (4s).
		// Entry is 2s old — not yet expired (TTL=4s), so cleanup must keep it.
		time.Sleep(2*time.Second + 100*time.Millisecond)
		synctest.Wait()

		if !c.Seen("interval-key") {
			t.Error("Seen(\"interval-key\") after 1 cleanup interval = false, want true (not yet expired)")
		}

		// Advance past the second cleanup interval (total > TTL + interval = 6s).
		// Entry is now older than TTL; next cleanup tick should evict it.
		time.Sleep(4 * time.Second)
		synctest.Wait()

		// After the entry has been evicted, Seen should return false (new entry).
		if c.Seen("interval-key") {
			t.Error("Seen(\"interval-key\") after TTL+interval = true, want false (should be evicted)")
		}
	})
}

// TestDeduplicationCache_MultipleKeys_Synctest verifies that expiry is per-key:
// a key inserted later survives when an earlier key is evicted.
func TestDeduplicationCache_MultipleKeys_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const ttl = 4 * time.Second

		c := NewDeduplicationCache(ttl)
		defer c.Stop()

		// Insert key-A at virtual t=0.
		if c.Seen("key-A") {
			t.Fatal("Seen(\"key-A\") first call = true, want false")
		}

		// Advance to t=3s — past one cleanup interval (2s), not past TTL.
		time.Sleep(3 * time.Second)
		synctest.Wait()

		// Insert key-B at virtual t=3s.
		if c.Seen("key-B") {
			t.Fatal("Seen(\"key-B\") first call = true, want false")
		}

		// Advance to t=7s total:
		//   key-A is 7s old  > TTL(4s) → should be evicted by cleanup at t=6s
		//   key-B is 4s old == TTL(4s) → borderline; cleanup at t=6s sees it as exactly TTL, >TTL is false so it stays
		time.Sleep(4 * time.Second)
		synctest.Wait()

		// key-A should be gone (age 7s > TTL 4s, cleanup fired at t=6s).
		if c.Seen("key-A") {
			t.Error("Seen(\"key-A\") after eviction = true, want false")
		}

		// key-B should still be present (age 4s, not > TTL at cleanup time).
		if !c.Seen("key-B") {
			t.Error("Seen(\"key-B\") = false, want true (not yet expired at last cleanup tick)")
		}
	})
}

// TestDeduplicationCache_Stop_Synctest verifies that after Stop is called the
// cleanup goroutine exits. We confirm this by checking the done channel is
// drained: if the goroutine is still alive it will be blocked on ticker.C or
// done, and synctest.Wait() will return only when all goroutines in the bubble
// are blocked. If Stop doesn't cause the goroutine to exit, synctest.Wait()
// would still succeed (goroutine is blocked on select), so we verify indirectly
// by checking that advancing time after Stop does NOT evict a key that was
// inserted after Stop (the cleanup goroutine must have exited).
func TestDeduplicationCache_Stop_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const ttl = 2 * time.Second

		c := NewDeduplicationCache(ttl)

		// Insert a key before stopping.
		if c.Seen("pre-stop-key") {
			t.Fatal("Seen(\"pre-stop-key\") first call = true, want false")
		}

		// Stop the cleanup goroutine.
		c.Stop()
		synctest.Wait()

		// Advance time well past TTL + cleanup interval.
		// Since the goroutine has exited, no cleanup will run and the key persists.
		time.Sleep(ttl + 2*time.Second)
		synctest.Wait()

		// Key must still be present because cleanup goroutine has exited.
		if !c.Seen("pre-stop-key") {
			t.Error("Seen(\"pre-stop-key\") after Stop + time advance = false, want true (no cleanup after Stop)")
		}
	})
}
