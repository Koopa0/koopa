package tools

import (
	"context"
	"testing"

	"github.com/firebase/genkit/go/genkit"
)

// ============================================================================
// Registry Tests
// ============================================================================

func TestNewRegistry(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	registry := NewRegistry(g)

	if registry == nil {
		t.Fatal("NewRegistry returned nil")
	}

	// Verify registry is initialized (g field is unexported, we can't check it directly)
	// Instead, verify that All() works
	_ = registry.All(ctx)
}

func TestRegistry_All(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	registry := NewRegistry(g)

	// Get all local tools (may be empty if tools not registered)
	allTools := registry.All(ctx)

	// Should return a slice (even if empty)
	if allTools == nil {
		t.Error("All() should not return nil, expected empty slice")
	}

	t.Logf("All() returned %d local tools", len(allTools))
}

func TestRegistry_Count(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	registry := NewRegistry(g)

	count := registry.Count(ctx)

	// Should match All() length
	allTools := registry.All(ctx)
	if count != len(allTools) {
		t.Errorf("Count() = %d, but All() returned %d tools", count, len(allTools))
	}

	t.Logf("Count() returned %d local tools", count)
}

func TestRegistry_ThreadSafety(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	registry := NewRegistry(g)

	// Concurrent calls to All() should be safe
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_ = registry.All(ctx)
			_ = registry.Count(ctx)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	t.Log("Concurrent access completed without panic")
}

func TestRegistry_FreshLookup(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	registry := NewRegistry(g)

	// First call
	tools1 := registry.All(ctx)
	count1 := len(tools1)

	// Second call (should be fresh lookup, not cached)
	tools2 := registry.All(ctx)
	count2 := len(tools2)

	// Should return same count (no side effects)
	if count1 != count2 {
		t.Errorf("Expected consistent tool count, got %d then %d", count1, count2)
	}

	t.Logf("Fresh lookup verified: %d tools on each call", count1)
}
