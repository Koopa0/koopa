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
