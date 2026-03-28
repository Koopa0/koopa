package budget

import (
	"errors"
	"sync"
	"testing"
)

func TestReserve(t *testing.T) {
	tests := []struct {
		name    string
		limit   int64
		preload int64
		reserve int64
		wantErr bool
	}{
		{name: "within budget", limit: 1000, preload: 0, reserve: 500},
		{name: "exact limit", limit: 1000, preload: 500, reserve: 500},
		{name: "over budget", limit: 1000, preload: 500, reserve: 501, wantErr: true},
		{name: "already at limit", limit: 1000, preload: 1000, reserve: 1, wantErr: true},
		{name: "zero reserve", limit: 1000, preload: 999, reserve: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := New(tt.limit)
			if tt.preload > 0 {
				if err := b.Reserve(tt.preload); err != nil {
					t.Fatalf("Reserve(%d) preload: %v", tt.preload, err)
				}
			}
			err := b.Reserve(tt.reserve)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrOverBudget) {
					t.Fatalf("Reserve(%d) = %v, want ErrOverBudget", tt.reserve, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Reserve(%d) unexpected error: %v", tt.reserve, err)
			}
		})
	}
}

func TestReserveUsed(t *testing.T) {
	b := New(10000)
	if got := b.Used(); got != 0 {
		t.Fatalf("Used() = %d, want 0", got)
	}
	if err := b.Reserve(100); err != nil {
		t.Fatalf("Reserve(100) unexpected error: %v", err)
	}
	if err := b.Reserve(200); err != nil {
		t.Fatalf("Reserve(200) unexpected error: %v", err)
	}
	if got := b.Used(); got != 300 {
		t.Fatalf("Used() = %d, want 300", got)
	}
}

func TestReset(t *testing.T) {
	b := New(10000)
	if err := b.Reserve(5000); err != nil {
		t.Fatalf("Reserve(5000) unexpected error: %v", err)
	}
	b.Reset()
	if got := b.Used(); got != 0 {
		t.Fatalf("Used() after Reset() = %d, want 0", got)
	}
	if err := b.Reserve(10000); err != nil {
		t.Fatalf("Reserve(10000) after Reset() unexpected error: %v", err)
	}
}

func TestReserveConcurrent(t *testing.T) {
	t.Parallel()
	b := New(100)
	var wg sync.WaitGroup
	var successCount int64
	var mu sync.Mutex

	// 50 goroutines each trying to reserve 3 tokens
	for range 50 {
		wg.Go(func() {
			if err := b.Reserve(3); err == nil {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	if successCount > 33 {
		t.Fatalf("Reserve allowed %d reservations of 3 from limit 100 (max 33)", successCount)
	}
	if b.Used() > 100 {
		t.Fatalf("Used() = %d, exceeded limit 100", b.Used())
	}
}
