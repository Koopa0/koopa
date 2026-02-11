package chat

import (
	"errors"
	"testing"
)

// TestSentinelErrors_CanBeChecked tests that sentinel errors work correctly with errors.Is
func TestSentinelErrors_CanBeChecked(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		sentinel error
	}{
		{name: "ErrInvalidSession", err: ErrInvalidSession, sentinel: ErrInvalidSession},
		{name: "ErrExecutionFailed", err: ErrExecutionFailed, sentinel: ErrExecutionFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !errors.Is(tt.err, tt.sentinel) {
				t.Errorf("errors.Is(%v, %v) = false, want true", tt.err, tt.sentinel)
			}
		})
	}
}

// TestWrappedErrors_PreserveSentinel tests that wrapped errors preserve sentinel checking
func TestWrappedErrors_PreserveSentinel(t *testing.T) {
	t.Parallel()

	t.Run("wrapped invalid session error", func(t *testing.T) {
		t.Parallel()
		err := errors.New("original error")
		wrapped := errors.Join(ErrInvalidSession, err)
		if !errors.Is(wrapped, ErrInvalidSession) {
			t.Errorf("errors.Is(wrapped, ErrInvalidSession) = false, want true")
		}
	})

	t.Run("wrapped execution failed error", func(t *testing.T) {
		t.Parallel()
		err := errors.New("LLM timeout")
		wrapped := errors.Join(ErrExecutionFailed, err)
		if !errors.Is(wrapped, ErrExecutionFailed) {
			t.Errorf("errors.Is(wrapped, ErrExecutionFailed) = false, want true")
		}
	})
}
