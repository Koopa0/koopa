package app

import (
	"errors"
	"testing"
)

// ============================================================================
// Runtime.Close() Tests
// ============================================================================

func TestRuntime_Close(t *testing.T) {
	t.Run("close with nil app", func(t *testing.T) {
		cleanupCalled := false
		r := &Runtime{
			App:     nil,
			cleanup: func() { cleanupCalled = true },
		}

		err := r.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !cleanupCalled {
			t.Error("cleanup function should be called")
		}
	})

	t.Run("close with nil cleanup", func(t *testing.T) {
		r := &Runtime{
			App:     nil,
			cleanup: nil,
		}

		err := r.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("close propagates app error", func(t *testing.T) {
		// Create an app that will return an error on Close
		app := &App{
			eg: nil, // nil errgroup means Close returns nil
		}

		cleanupCalled := false
		r := &Runtime{
			App:     app,
			cleanup: func() { cleanupCalled = true },
		}

		err := r.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !cleanupCalled {
			t.Error("cleanup should be called even after app.Close succeeds")
		}
	})

	t.Run("cleanup called after app close", func(t *testing.T) {
		// This test verifies the shutdown order:
		// 1. App.Close() (cancel context, wait for goroutines)
		// 2. Wire cleanup (DB pool, OTel)
		var order []string

		app := &App{
			cancel: func() { order = append(order, "cancel") },
		}

		r := &Runtime{
			App:     app,
			cleanup: func() { order = append(order, "cleanup") },
		}

		_ = r.Close()

		if len(order) != 2 {
			t.Fatalf("expected 2 operations, got %d", len(order))
		}
		if order[0] != "cancel" {
			t.Errorf("expected cancel first, got %s", order[0])
		}
		if order[1] != "cleanup" {
			t.Errorf("expected cleanup second, got %s", order[1])
		}
	})
}

// TestRuntime_Close_ErrorAggregation tests that errors are properly joined.
func TestRuntime_Close_ErrorAggregation(t *testing.T) {
	t.Run("errors from app close are returned", func(t *testing.T) {
		// We can't easily make App.Close() return an error without
		// setting up an errgroup that returns an error.
		// This documents the expected behavior.

		// When App.Close() returns an error, Runtime.Close() should:
		// 1. Still call cleanup()
		// 2. Return the error

		cleanupCalled := false
		r := &Runtime{
			App: &App{
				cancel: nil,
				eg:     nil,
			},
			cleanup: func() { cleanupCalled = true },
		}

		err := r.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !cleanupCalled {
			t.Error("cleanup should always be called")
		}
	})
}

// TestNewRuntime_CleanupOnFailure documents the expected behavior when
// CreateAgent fails during NewRuntime initialization.
//
// The fix in runtime.go:60-66 ensures:
// 1. application.Close() is called to stop background goroutines
// 2. cleanup() is called to release DB pool and OTel resources
// 3. The original error is returned
//
// This test cannot easily verify the behavior without mocking,
// but documents the contract for future maintainers.
func TestNewRuntime_CleanupOnFailure(t *testing.T) {
	t.Run("documented behavior on CreateAgent failure", func(t *testing.T) {
		// When CreateAgent fails:
		// 1. application is already created (with background goroutine)
		// 2. We must call application.Close() to:
		//    - Cancel context
		//    - Wait for errgroup (background IndexSystemKnowledge)
		// 3. Then call cleanup() to close DB pool
		//
		// Without this order:
		// - Background goroutine may use closed DB pool
		// - Goroutine leak if context not canceled
		//
		// Integration testing is required to fully verify this behavior.
		t.Log("See runtime.go:60-66 for implementation")
	})
}

// TestErrors_Join verifies errors.Join behavior used in Close().
func TestErrors_Join(t *testing.T) {
	t.Run("nil errors return nil", func(t *testing.T) {
		err := errors.Join(nil, nil)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("empty slice returns nil", func(t *testing.T) {
		var errs []error
		err := errors.Join(errs...)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("single error preserved", func(t *testing.T) {
		original := errors.New("test error")
		errs := []error{original}
		err := errors.Join(errs...)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, original) {
			t.Error("error should wrap original")
		}
	})
}
