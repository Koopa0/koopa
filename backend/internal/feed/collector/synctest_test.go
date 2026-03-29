package collector

import (
	"testing"
	"testing/synctest"
	"time"
)

// TestDomainLimiter_IdleEviction_Synctest verifies that domain entries idle for
// longer than domainIdleTimeout (30 minutes) are evicted by the background
// cleanup goroutine, which runs every 5 minutes.
func TestDomainLimiter_IdleEviction_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := NewDomainLimiter(100 * time.Millisecond)
		defer d.Stop()

		ctx := t.Context()

		// Register two domains.
		if err := d.Wait(ctx, "https://alpha.example.com/feed"); err != nil {
			t.Fatalf("Wait(alpha) = %v, want nil", err)
		}
		if err := d.Wait(ctx, "https://beta.example.com/feed"); err != nil {
			t.Fatalf("Wait(beta) = %v, want nil", err)
		}

		synctest.Wait()

		// Advance just past 5 minutes — first cleanup tick fires, but entries are
		// only ~5 minutes old, not yet past domainIdleTimeout (30 minutes).
		time.Sleep(5*time.Minute + time.Second)
		synctest.Wait()

		d.mu.Lock()
		sizeAfterFirstTick := len(d.limiters)
		d.mu.Unlock()

		if sizeAfterFirstTick != 2 {
			t.Errorf("limiter count after first tick = %d, want 2 (not yet idle)", sizeAfterFirstTick)
		}

		// Advance to 31 minutes total — entries are now 31 minutes idle (> 30 min timeout).
		// The cleanup tick at 35 minutes will evict them; advance to 35m to be safe.
		time.Sleep(30 * time.Minute)
		synctest.Wait()

		d.mu.Lock()
		sizeAfterEviction := len(d.limiters)
		d.mu.Unlock()

		if sizeAfterEviction != 0 {
			t.Errorf("limiter count after idle eviction = %d, want 0", sizeAfterEviction)
		}
	})
}

// TestDomainLimiter_ActiveDomainNotEvicted_Synctest verifies that a domain that
// is accessed periodically is not evicted by the cleanup goroutine.
func TestDomainLimiter_ActiveDomainNotEvicted_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Use a 100ms rate interval so Wait returns immediately in tests.
		d := NewDomainLimiter(100 * time.Millisecond)
		defer d.Stop()

		ctx := t.Context()

		// Register domain and record initial access.
		if err := d.Wait(ctx, "https://active.example.com/feed"); err != nil {
			t.Fatalf("Wait(active, first) = %v, want nil", err)
		}

		synctest.Wait()

		// Advance 25 minutes — before idle timeout (30 min). Then re-access the
		// domain to reset its lastUsed timestamp.
		time.Sleep(25 * time.Minute)
		synctest.Wait()

		// Re-access at t=25min to reset lastUsed.
		time.Sleep(100 * time.Millisecond) // let rate limiter token refill
		synctest.Wait()
		if err := d.Wait(ctx, "https://active.example.com/feed"); err != nil {
			t.Fatalf("Wait(active, second) = %v, want nil", err)
		}

		// Advance another 29 minutes (total t=54min).
		// Entry's lastUsed was reset at t=25min so it's only 29 minutes idle —
		// below the 30-minute threshold. The cleanup tick at t=55min has not fired.
		time.Sleep(29 * time.Minute)
		synctest.Wait()

		d.mu.Lock()
		_, present := d.limiters["active.example.com"]
		d.mu.Unlock()

		if !present {
			t.Error("active.example.com was evicted despite recent access, want present")
		}
	})
}

// TestDomainLimiter_CleanupGoroutineExits_Synctest verifies that the background
// cleanup goroutine exits when Stop is called, and that entries are no longer
// evicted after the goroutine exits.
func TestDomainLimiter_CleanupGoroutineExits_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := NewDomainLimiter(100 * time.Millisecond)

		ctx := t.Context()
		if err := d.Wait(ctx, "https://example.com/feed"); err != nil {
			t.Fatalf("Wait = %v, want nil", err)
		}

		synctest.Wait()

		// Stop the cleanup goroutine.
		d.Stop()
		synctest.Wait()

		// Advance far past domainIdleTimeout (30 min). Because the goroutine has
		// exited, no eviction should occur.
		time.Sleep(60 * time.Minute)
		synctest.Wait()

		d.mu.Lock()
		_, present := d.limiters["example.com"]
		d.mu.Unlock()

		if !present {
			t.Error("example.com was evicted after Stop, want present (cleanup goroutine exited)")
		}
	})
}

// TestDomainLimiter_PartialEviction_Synctest verifies that only truly idle
// entries are evicted, while recently-accessed entries survive the cleanup pass.
func TestDomainLimiter_PartialEviction_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := NewDomainLimiter(100 * time.Millisecond)
		defer d.Stop()

		ctx := t.Context()

		// Register "old" domain at t=0.
		if err := d.Wait(ctx, "https://old.example.com/feed"); err != nil {
			t.Fatalf("Wait(old) = %v, want nil", err)
		}

		synctest.Wait()

		// Advance to t=29min — old domain is 29 minutes idle.
		time.Sleep(29 * time.Minute)
		synctest.Wait()

		// Register "new" domain at t=29min — it's only seconds old.
		if err := d.Wait(ctx, "https://new.example.com/feed"); err != nil {
			t.Fatalf("Wait(new) = %v, want nil", err)
		}

		// Advance to t=35min — old domain is 35 min idle (> 30 min), new is 6 min.
		// Cleanup tick at t=35min should evict old but keep new.
		time.Sleep(6 * time.Minute)
		synctest.Wait()

		d.mu.Lock()
		_, oldPresent := d.limiters["old.example.com"]
		_, newPresent := d.limiters["new.example.com"]
		d.mu.Unlock()

		if oldPresent {
			t.Error("old.example.com present after 35min idle, want evicted")
		}
		if !newPresent {
			t.Error("new.example.com missing after 6min idle, want present")
		}
	})
}
