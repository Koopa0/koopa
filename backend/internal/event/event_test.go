package event

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setup     func(*Bus)
		event     string
		payload   any
		wantErr   bool
		wantCalls int
	}{
		{
			name: "handler receives correct event and payload",
			setup: func(b *Bus) {
				b.On("order.created", func(_ context.Context, p any) error {
					if diff := cmp.Diff("item-1", p); diff != "" {
						t.Errorf("payload mismatch (-want +got):\n%s", diff)
					}
					return nil
				})
			},
			event:     "order.created",
			payload:   "item-1",
			wantCalls: 1,
		},
		{
			name: "multiple handlers called in order",
			setup: func(b *Bus) {
				var order []int
				b.On("step", func(_ context.Context, _ any) error {
					order = append(order, 1)
					return nil
				})
				b.On("step", func(_ context.Context, _ any) error {
					order = append(order, 2)
					return nil
				})
				b.On("step", func(_ context.Context, _ any) error {
					order = append(order, 3)
					if diff := cmp.Diff([]int{1, 2, 3}, order); diff != "" {
						t.Errorf("call order mismatch (-want +got):\n%s", diff)
					}
					return nil
				})
			},
			event:     "step",
			payload:   nil,
			wantCalls: 3,
		},
		{
			name: "handler errors are collected",
			setup: func(b *Bus) {
				b.On("fail", func(_ context.Context, _ any) error {
					return errors.New("first")
				})
				b.On("fail", func(_ context.Context, _ any) error {
					return nil // succeeds
				})
				b.On("fail", func(_ context.Context, _ any) error {
					return errors.New("third")
				})
			},
			event:     "fail",
			payload:   nil,
			wantErr:   true,
			wantCalls: 3,
		},
		{
			name:      "unknown event returns nil",
			setup:     func(_ *Bus) {},
			event:     "does.not.exist",
			payload:   nil,
			wantCalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32
			bus := New()

			// wrap setup to count calls
			original := tt.setup
			inner := bus
			original(inner)

			// re-wrap handlers with call counter
			wrapped := New()
			origHandlers := inner.handlers
			for ev, fns := range origHandlers {
				for _, fn := range fns {
					wrapped.On(ev, func(ctx context.Context, p any) error {
						calls.Add(1)
						return fn(ctx, p)
					})
				}
			}

			err := wrapped.Emit(t.Context(), tt.event, tt.payload)

			if (err != nil) != tt.wantErr {
				t.Errorf("Emit() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got := int(calls.Load()); got != tt.wantCalls {
				t.Errorf("handler calls = %d, want %d", got, tt.wantCalls)
			}
		})
	}
}

func TestBus_ErrorContainsBoth(t *testing.T) {
	t.Parallel()

	bus := New()
	errFirst := errors.New("first")
	errSecond := errors.New("second")

	bus.On("multi-err", func(_ context.Context, _ any) error { return errFirst })
	bus.On("multi-err", func(_ context.Context, _ any) error { return errSecond })

	err := bus.Emit(t.Context(), "multi-err", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errFirst) {
		t.Errorf("joined error should contain errFirst")
	}
	if !errors.Is(err, errSecond) {
		t.Errorf("joined error should contain errSecond")
	}
}

func TestBus_ConcurrentEmitAndOn(t *testing.T) {
	t.Parallel()

	bus := New()
	var wg sync.WaitGroup

	// register some initial handlers
	for range 10 {
		bus.On("concurrent", func(_ context.Context, _ any) error {
			return nil
		})
	}

	// concurrent emits and registrations
	for range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = bus.Emit(t.Context(), "concurrent", "data")
		}()
		go func() {
			defer wg.Done()
			bus.On("concurrent", func(_ context.Context, _ any) error {
				return nil
			})
		}()
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Edge cases requested in test-writer spec
// ---------------------------------------------------------------------------

func TestBus_EmitNilPayload(t *testing.T) {
	t.Parallel()

	bus := New()
	var received any = "sentinel" // confirm nil overwrites it

	bus.On("nil-payload", func(_ context.Context, p any) error {
		received = p
		return nil
	})

	if err := bus.Emit(t.Context(), "nil-payload", nil); err != nil {
		t.Fatalf("Emit() with nil payload returned error: %v", err)
	}
	if received != nil {
		t.Errorf("handler received %v, want nil", received)
	}
}

func TestBus_EmitEmptyEventName(t *testing.T) {
	t.Parallel()

	bus := New()
	var called bool

	// Register handler for empty string event name.
	bus.On("", func(_ context.Context, _ any) error {
		called = true
		return nil
	})

	// Emitting "" fires the handler registered under "".
	if err := bus.Emit(t.Context(), "", "payload"); err != nil {
		t.Fatalf("Emit(%q) unexpected error: %v", "", err)
	}
	if !called {
		t.Error("Emit(\"\") did not call handler registered for empty event name")
	}

	// Emitting a different event does NOT fire the empty-name handler.
	called = false
	if err := bus.Emit(t.Context(), "other", "payload"); err != nil {
		t.Fatalf("Emit(%q) unexpected error: %v", "other", err)
	}
	if called {
		t.Error("Emit(\"other\") called handler registered for empty event name")
	}
}

// TestBus_OnDuringEmit_DoesNotDeadlock verifies that registering a new handler
// while another goroutine is inside Emit does not deadlock.
// Emit holds an RLock; On acquires a write Lock.
// The RWMutex guarantees this is safe — On waits until Emit finishes its read.
func TestBus_OnDuringEmit_DoesNotDeadlock(t *testing.T) {
	t.Parallel()

	bus := New()
	done := make(chan struct{})

	// Handler that signals we are inside Emit, then blocks until the test allows it to continue.
	inside := make(chan struct{})
	proceed := make(chan struct{})

	bus.On("event", func(ctx context.Context, _ any) error {
		close(inside) // signal: we are inside Emit
		<-proceed     // wait: test will close this after calling On
		return nil
	})

	// Start Emit in a separate goroutine.
	go func() {
		defer close(done)
		_ = bus.Emit(t.Context(), "event", nil)
	}()

	// Wait until the handler is executing (i.e., Emit holds its RLock).
	<-inside

	// Register a new handler from a different goroutine.
	// This MUST NOT deadlock — On will block waiting for Emit's RLock to be released,
	// but the test unblocks Emit shortly after.
	registered := make(chan struct{})
	go func() {
		bus.On("event", func(_ context.Context, _ any) error { return nil })
		close(registered)
	}()

	// Allow Emit's handler to finish.
	close(proceed)

	// Wait for both goroutines to complete within a reasonable time.
	select {
	case <-done:
	case <-t.Context().Done():
		t.Fatal("Emit goroutine did not finish: possible deadlock")
	}
	select {
	case <-registered:
	case <-t.Context().Done():
		t.Fatal("On goroutine did not finish: possible deadlock")
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkBus_Emit_10Handlers(b *testing.B) {
	bus := New()
	for range 10 {
		bus.On("bench", func(_ context.Context, _ any) error {
			return nil
		})
	}
	ctx := context.Background()
	for b.Loop() {
		_ = bus.Emit(ctx, "bench", "payload")
	}
}

func BenchmarkBus_Emit_NoHandlers(b *testing.B) {
	bus := New()
	ctx := context.Background()
	for b.Loop() {
		_ = bus.Emit(ctx, "no-handlers", nil)
	}
}

func BenchmarkBus_On(b *testing.B) {
	bus := New()
	fn := func(_ context.Context, _ any) error { return nil }
	for b.Loop() {
		bus.On("bench", fn)
	}
}
