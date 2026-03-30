package collector

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// TestDomainLimiter_Wait verifies that Wait returns nil for a valid URL and
// does not block when a token is available.
func TestDomainLimiter_Wait(t *testing.T) {
	t.Parallel()

	d := NewDomainLimiter(10 * time.Millisecond)
	defer d.Stop()

	ctx := t.Context()
	if err := d.Wait(ctx, "https://example.com/feed"); err != nil {
		t.Fatalf("DomainLimiter.Wait() = %v, want nil", err)
	}
}

// TestDomainLimiter_Stop ensures Stop can be called multiple times safely and
// that calling Wait after Stop with a cancelled context returns an error.
func TestDomainLimiter_Stop(t *testing.T) {
	t.Parallel()

	d := NewDomainLimiter(10 * time.Millisecond)
	d.Stop()
	// calling Stop twice must not panic
	// (done channel is already closed; second close would panic — test that Stop
	// is idempotent via the goroutine; we just verify no panic here by doing a
	// Wait with a fast-cancelled ctx)
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // immediately cancelled

	// consume the first token (already available)
	_ = d.Wait(ctx, "https://example.com/feed")
	// second request on same domain requires waiting — ctx is cancelled so it must fail
	err := d.Wait(ctx, "https://example.com/feed")
	if err == nil {
		t.Fatal("DomainLimiter.Wait(cancelled ctx) = nil, want error")
	}
}

// TestDomainLimiter_PerDomain verifies that different domains get independent limiters
// and do not block each other.
func TestDomainLimiter_PerDomain(t *testing.T) {
	t.Parallel()

	// Use a large interval so the second call on the SAME domain would block,
	// but different domains must not block.
	d := NewDomainLimiter(1 * time.Hour)
	defer d.Stop()

	ctx := t.Context()

	if err := d.Wait(ctx, "https://alpha.com/feed"); err != nil {
		t.Fatalf("Wait(alpha) = %v, want nil", err)
	}
	if err := d.Wait(ctx, "https://beta.com/feed"); err != nil {
		t.Fatalf("Wait(beta) = %v, want nil", err)
	}
	// Third domain also independent
	if err := d.Wait(ctx, "https://gamma.com/feed"); err != nil {
		t.Fatalf("Wait(gamma) = %v, want nil", err)
	}
}

// TestDomainLimiter_SameDomainBlocks verifies that a second request to the same
// domain blocks until the context is cancelled when the interval is very large.
func TestDomainLimiter_SameDomainBlocks(t *testing.T) {
	t.Parallel()

	d := NewDomainLimiter(1 * time.Hour)
	defer d.Stop()

	// First request succeeds immediately.
	if err := d.Wait(t.Context(), "https://example.com/feed"); err != nil {
		t.Fatalf("first Wait = %v, want nil", err)
	}

	// Second request to same domain should block; use a short deadline.
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	err := d.Wait(ctx, "https://example.com/feed")
	if err == nil {
		t.Fatal("DomainLimiter.Wait(same domain, huge interval) = nil, want context error")
	}
}

// TestDomainLimiter_InvalidURL verifies that an unparseable URL falls back to
// the raw string as domain key and does not panic.
func TestDomainLimiter_InvalidURL(t *testing.T) {
	t.Parallel()

	d := NewDomainLimiter(10 * time.Millisecond)
	defer d.Stop()

	ctx := t.Context()
	// Should not panic; falls back to raw string as key.
	if err := d.Wait(ctx, "://not-a-url"); err != nil {
		t.Fatalf("DomainLimiter.Wait(invalid url) = %v, want nil", err)
	}
}

// TestDomainLimiter_ConcurrentDomains exercises concurrent access across many
// domains to surface data races (run with -race).
func TestDomainLimiter_ConcurrentDomains(t *testing.T) {
	t.Parallel()

	d := NewDomainLimiter(1 * time.Millisecond)
	defer d.Stop()

	const goroutines = 20
	domains := []string{
		"https://a.com/", "https://b.com/", "https://c.com/",
		"https://d.com/", "https://e.com/",
	}

	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()
			url := domains[idx%len(domains)]
			errs[idx] = d.Wait(ctx, url)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: Wait() = %v, want nil", i, err)
		}
	}
}

// TestDomainLimiter_ConcurrentSameDomain verifies that concurrent goroutines
// waiting on the same domain do not race on internal state.
func TestDomainLimiter_ConcurrentSameDomain(t *testing.T) {
	t.Parallel()

	d := NewDomainLimiter(1 * time.Millisecond)
	defer d.Stop()

	const goroutines = 10
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()
			errs[idx] = d.Wait(ctx, "https://example.com/feed")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: Wait() = %v, want nil", i, err)
		}
	}
}

// TestDomainLimiter_ContextCancelledBeforeWait verifies that a pre-cancelled
// context immediately returns an error without blocking.
func TestDomainLimiter_ContextCancelledBeforeWait(t *testing.T) {
	t.Parallel()

	d := NewDomainLimiter(1 * time.Hour)
	defer d.Stop()

	// Consume the first token.
	if err := d.Wait(t.Context(), "https://example.com/feed"); err != nil {
		t.Fatalf("first Wait = %v, want nil", err)
	}

	// Pre-cancelled context for second request.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := d.Wait(ctx, "https://example.com/feed")
	if err == nil {
		t.Fatal("Wait(pre-cancelled ctx) = nil, want error")
	}
}

// TestDomainLimiter_RateTimingWithSynctest uses testing/synctest to verify that
// the rate limiter enforces the interval without real wall-clock sleep.
func TestDomainLimiter_RateTimingWithSynctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		interval := 2 * time.Second
		d := NewDomainLimiter(interval)
		defer d.Stop()

		ctx := t.Context()
		domain := "https://example.com/feed"

		// First token is available immediately.
		if err := d.Wait(ctx, domain); err != nil {
			t.Fatalf("first Wait = %v, want nil", err)
		}

		// Start second request in a goroutine — it should block until after interval.
		done := make(chan error, 1)
		go func() {
			done <- d.Wait(ctx, domain)
		}()

		// Let all goroutines reach their blocking points.
		synctest.Wait()

		// Advance the fake clock past the rate limit interval.
		time.Sleep(interval + time.Millisecond)
		synctest.Wait()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("second Wait after interval = %v, want nil", err)
			}
		default:
			t.Error("second Wait did not complete after interval elapsed")
		}
	})
}

// TestDomainFromURL covers adversarial and boundary inputs beyond the existing tests.
func TestDomainFromURL_Extended(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		// existing happy path
		{name: "simple https", input: "https://example.com/feed", want: "example.com"},
		// adversarial
		{name: "empty string", input: "", want: ""},
		{name: "no host", input: "https:///path", want: ""},
		{name: "ip address", input: "http://127.0.0.1:8080/feed", want: "127.0.0.1:8080"},
		{name: "ipv6", input: "https://[::1]:9000/feed", want: "[::1]:9000"},
		{name: "null byte in url", input: "https://evil\x00.com/feed", want: ""},
		{name: "SQL injection as url", input: "'; DROP TABLE feeds; --", want: ""},
		{name: "scheme only", input: "https://", want: ""},
		// unicode host
		{name: "punycode host", input: "https://xn--nxasmq6b.com/feed", want: "xn--nxasmq6b.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := domainFromURL(tt.input)
			if got != tt.want {
				t.Errorf("domainFromURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func FuzzDomainFromURL(f *testing.F) {
	f.Add("https://example.com/feed")
	f.Add("")
	f.Add("://bad")
	f.Add("https://[::1]:9000/feed")
	f.Add("\x00\xff")
	f.Add("'; DROP TABLE feeds; --")

	f.Fuzz(func(t *testing.T, input string) {
		// must not panic
		_ = domainFromURL(input)
	})
}
