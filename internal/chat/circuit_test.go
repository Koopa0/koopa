package chat

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDefaultCircuitBreakerConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultCircuitBreakerConfig()

	if cfg.FailureThreshold <= 0 {
		t.Errorf("FailureThreshold should be positive, got %d", cfg.FailureThreshold)
	}
	if cfg.SuccessThreshold <= 0 {
		t.Errorf("SuccessThreshold should be positive, got %d", cfg.SuccessThreshold)
	}
	if cfg.Timeout <= 0 {
		t.Errorf("Timeout should be positive, got %v", cfg.Timeout)
	}
}

func TestNewCircuitBreaker_AppliesDefaults(t *testing.T) {
	t.Parallel()

	// Zero config should use defaults
	cb := NewCircuitBreaker(CircuitBreakerConfig{})

	if cb.failureThreshold <= 0 {
		t.Error("should apply default failure threshold")
	}
	if cb.successThreshold <= 0 {
		t.Error("should apply default success threshold")
	}
	if cb.timeout <= 0 {
		t.Error("should apply default timeout")
	}
	if cb.State() != CircuitClosed {
		t.Error("should start in closed state")
	}
}

func TestCircuitBreaker_ClosedState(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	})

	// Should allow requests when closed
	if err := cb.Allow(); err != nil {
		t.Errorf("Allow() should succeed when closed, got %v", err)
	}

	// State should be closed
	if cb.State() != CircuitClosed {
		t.Error("should be in closed state")
	}
}

func TestCircuitBreaker_OpensAfterFailures(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	})

	// Record failures below threshold
	cb.Failure()
	cb.Failure()
	if cb.State() != CircuitClosed {
		t.Error("should remain closed below threshold")
	}

	// Third failure should open circuit
	cb.Failure()
	if cb.State() != CircuitOpen {
		t.Error("should open after reaching threshold")
	}

	// Should reject requests when open
	if err := cb.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("Allow() should return ErrCircuitOpen, got %v", err)
	}
}

func TestCircuitBreaker_SuccessResetFailures(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	})

	// Record some failures
	cb.Failure()
	cb.Failure()

	// Success should reset failure count
	cb.Success()

	// Now need 3 more failures to open
	cb.Failure()
	cb.Failure()
	if cb.State() != CircuitClosed {
		t.Error("should remain closed after success reset failures")
	}

	cb.Failure()
	if cb.State() != CircuitOpen {
		t.Error("should open after 3 consecutive failures")
	}
}

func TestCircuitBreaker_HalfOpenAfterTimeout(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 2,
		Timeout:          50 * time.Millisecond,
	})

	// Open the circuit
	cb.Failure()
	cb.Failure()
	if cb.State() != CircuitOpen {
		t.Fatal("circuit should be open")
	}

	// Wait for timeout
	time.Sleep(60 * time.Millisecond)

	// Allow should transition to half-open
	if err := cb.Allow(); err != nil {
		t.Errorf("Allow() should succeed after timeout, got %v", err)
	}

	if cb.State() != CircuitHalfOpen {
		t.Error("should be in half-open state after timeout")
	}
}

func TestCircuitBreaker_HalfOpenToClose(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 2,
		Timeout:          50 * time.Millisecond,
	})

	// Open the circuit
	cb.Failure()
	cb.Failure()

	// Wait for timeout and transition to half-open
	time.Sleep(60 * time.Millisecond)
	_ = cb.Allow()

	if cb.State() != CircuitHalfOpen {
		t.Fatal("should be half-open")
	}

	// First success
	cb.Success()
	if cb.State() != CircuitHalfOpen {
		t.Error("should remain half-open after one success")
	}

	// Second success should close circuit
	cb.Success()
	if cb.State() != CircuitClosed {
		t.Error("should close after reaching success threshold")
	}
}

func TestCircuitBreaker_HalfOpenToOpen(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 2,
		Timeout:          50 * time.Millisecond,
	})

	// Open the circuit
	cb.Failure()
	cb.Failure()

	// Wait for timeout and transition to half-open
	time.Sleep(60 * time.Millisecond)
	_ = cb.Allow()

	if cb.State() != CircuitHalfOpen {
		t.Fatal("should be half-open")
	}

	// Failure in half-open should immediately open
	cb.Failure()
	if cb.State() != CircuitOpen {
		t.Error("should open immediately on failure in half-open state")
	}
}

func TestCircuitBreaker_Reset(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	})

	// Open the circuit
	cb.Failure()
	cb.Failure()
	if cb.State() != CircuitOpen {
		t.Fatal("should be open")
	}

	// Reset should close circuit
	cb.Reset()
	if cb.State() != CircuitClosed {
		t.Error("should be closed after reset")
	}

	// Should allow requests
	if err := cb.Allow(); err != nil {
		t.Errorf("Allow() should succeed after reset, got %v", err)
	}
}

func TestCircuitState_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state CircuitState
		want  string
	}{
		{state: CircuitClosed, want: "closed"},
		{state: CircuitOpen, want: "open"},
		{state: CircuitHalfOpen, want: "half-open"},
		{state: CircuitState(99), want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			if got := tt.state.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 100, // High threshold to avoid opening during test
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	})

	var wg sync.WaitGroup
	const goroutines = 50
	const operations = 100

	// Concurrent Allow, Success, Failure, and State calls
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operations; j++ {
				switch id % 4 {
				case 0:
					_ = cb.Allow()
				case 1:
					cb.Success()
				case 2:
					cb.Failure()
				case 3:
					_ = cb.State()
				}
			}
		}(i)
	}

	wg.Wait()
	// No race conditions should occur (run with -race flag)
}
