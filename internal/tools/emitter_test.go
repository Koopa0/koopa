package tools_test

import (
	"context"
	"testing"

	"github.com/koopa0/koopa/internal/tools"
)

// mockEmitter is a test implementation of ToolEventEmitter.
// Interface simplified to only tool name parameter.
type mockEmitter struct {
	startCalls    []string
	completeCalls []string
	errorCalls    []string
}

func (m *mockEmitter) OnToolStart(name string) {
	m.startCalls = append(m.startCalls, name)
}

func (m *mockEmitter) OnToolComplete(name string) {
	m.completeCalls = append(m.completeCalls, name)
}

func (m *mockEmitter) OnToolError(name string) {
	m.errorCalls = append(m.errorCalls, name)
}

// Verify mockEmitter implements ToolEventEmitter.
var _ tools.ToolEventEmitter = (*mockEmitter)(nil)

func TestContextWithEmitter(t *testing.T) {
	t.Parallel()

	t.Run("stores emitter in context", func(t *testing.T) {
		t.Parallel()

		emitter := &mockEmitter{}
		ctx := context.Background()

		ctxWithEmitter := tools.ContextWithEmitter(ctx, emitter)

		retrieved := tools.EmitterFromContext(ctxWithEmitter)
		if retrieved == nil {
			t.Fatal("expected emitter to be retrieved from context")
		}
		// Compare via interface method behavior instead of pointer equality
		retrieved.OnToolStart("test")
		if len(emitter.startCalls) != 1 {
			t.Error("retrieved emitter does not match stored emitter")
		}
	})

	t.Run("overwrites previous emitter", func(t *testing.T) {
		t.Parallel()

		emitter1 := &mockEmitter{}
		emitter2 := &mockEmitter{}

		ctx := tools.ContextWithEmitter(context.Background(), emitter1)
		ctx = tools.ContextWithEmitter(ctx, emitter2)

		retrieved := tools.EmitterFromContext(ctx)
		retrieved.OnToolStart("test")
		// emitter2 should receive the call, not emitter1
		if len(emitter2.startCalls) != 1 {
			t.Error("expected second emitter to overwrite first")
		}
		if len(emitter1.startCalls) != 0 {
			t.Error("first emitter should not receive calls")
		}
	})
}

func TestEmitterFromContext(t *testing.T) {
	t.Parallel()

	t.Run("returns nil for empty context", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		emitter := tools.EmitterFromContext(ctx)

		if emitter != nil {
			t.Error("expected nil emitter from empty context")
		}
	})

	t.Run("returns nil for wrong type in context", func(t *testing.T) {
		t.Parallel()

		// This tests the type assertion safety
		// We can't directly set a wrong type, but we can verify graceful nil handling
		ctx := context.Background()
		emitter := tools.EmitterFromContext(ctx)

		if emitter != nil {
			t.Error("expected nil for missing emitter")
		}
	})

	t.Run("returns stored emitter", func(t *testing.T) {
		t.Parallel()

		emitter := &mockEmitter{}
		ctx := tools.ContextWithEmitter(context.Background(), emitter)

		retrieved := tools.EmitterFromContext(ctx)
		retrieved.OnToolStart("verify")
		if len(emitter.startCalls) != 1 || emitter.startCalls[0] != "verify" {
			t.Error("did not retrieve correct emitter")
		}
	})
}

func TestEmitterInterface(t *testing.T) {
	t.Parallel()

	t.Run("OnToolStart records call", func(t *testing.T) {
		t.Parallel()

		emitter := &mockEmitter{}
		emitter.OnToolStart("web_search")

		if len(emitter.startCalls) != 1 {
			t.Fatalf("expected 1 start call, got %d", len(emitter.startCalls))
		}

		if emitter.startCalls[0] != "web_search" {
			t.Errorf("name = %q, want web_search", emitter.startCalls[0])
		}
	})

	t.Run("OnToolComplete records call", func(t *testing.T) {
		t.Parallel()

		emitter := &mockEmitter{}
		emitter.OnToolComplete("web_search")

		if len(emitter.completeCalls) != 1 {
			t.Fatalf("expected 1 complete call, got %d", len(emitter.completeCalls))
		}

		if emitter.completeCalls[0] != "web_search" {
			t.Errorf("name = %q, want web_search", emitter.completeCalls[0])
		}
	})

	t.Run("OnToolError records call", func(t *testing.T) {
		t.Parallel()

		emitter := &mockEmitter{}
		emitter.OnToolError("web_search")

		if len(emitter.errorCalls) != 1 {
			t.Fatalf("expected 1 error call, got %d", len(emitter.errorCalls))
		}

		if emitter.errorCalls[0] != "web_search" {
			t.Errorf("name = %q, want web_search", emitter.errorCalls[0])
		}
	})
}

func TestGracefulDegradation(t *testing.T) {
	t.Parallel()

	// This test documents the expected behavior when no emitter is set.
	// Tools should check for nil before calling emitter methods.
	t.Run("nil emitter allows graceful degradation", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		emitter := tools.EmitterFromContext(ctx)

		// Code pattern for graceful degradation:
		if emitter != nil {
			emitter.OnToolStart("test")
		}

		// No panic - this is the expected usage pattern
	})
}
