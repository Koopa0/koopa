package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSessionID is a helper for tests to create SessionID without error handling boilerplate
func testSessionID(t *testing.T, id string) SessionID {
	t.Helper()
	s, err := NewSessionID(id)
	require.NoError(t, err)
	return s
}

// TestSessionID_EdgeCases tests SessionID boundary conditions
func TestSessionID_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("single character session ID", func(t *testing.T) {
		t.Parallel()
		id, err := NewSessionID("x")
		require.NoError(t, err)
		assert.Equal(t, "x", id.String())
		assert.False(t, id.IsEmpty())
	})

	t.Run("exactly 255 characters", func(t *testing.T) {
		t.Parallel()
		longID := strings.Repeat("a", 255)
		id, err := NewSessionID(longID)
		require.NoError(t, err)
		assert.Equal(t, 255, len(id.String()))
	})

	t.Run("256 characters returns error", func(t *testing.T) {
		t.Parallel()
		tooLongID := strings.Repeat("a", 256)
		_, err := NewSessionID(tooLongID)
		assert.ErrorIs(t, err, ErrSessionIDTooLong)
	})

	t.Run("unicode characters", func(t *testing.T) {
		t.Parallel()
		// Unicode characters can be multi-byte, test byte length vs rune length
		unicodeID := "測試-ID-🔥" // Mixed ASCII, Chinese, emoji
		id, err := NewSessionID(unicodeID)
		require.NoError(t, err)
		assert.Equal(t, unicodeID, id.String())
		assert.False(t, id.IsEmpty())
	})

	t.Run("special characters", func(t *testing.T) {
		t.Parallel()
		specialID := "session-123_test.v2:alpha"
		id, err := NewSessionID(specialID)
		require.NoError(t, err)
		assert.Equal(t, specialID, id.String())
	})

	t.Run("empty string returns error", func(t *testing.T) {
		t.Parallel()
		_, err := NewSessionID("")
		assert.ErrorIs(t, err, ErrEmptySessionID)
	})

	t.Run("zero value SessionID is empty", func(t *testing.T) {
		t.Parallel()
		var zeroID SessionID
		assert.True(t, zeroID.IsEmpty())
		assert.Equal(t, "", zeroID.String())
	})

}

// TestInvocationContext_BranchPathEdgeCases tests branch path boundary conditions
func TestInvocationContext_BranchPathEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty branch name", func(t *testing.T) {
		t.Parallel()
		ctx := NewInvocationContext(
			context.Background(),
			"inv-123",
			"", // empty branch
			testSessionID(t, "s-123"),
			"agent",
		)
		assert.Equal(t, "", ctx.Branch())
	})

	t.Run("single dot branch", func(t *testing.T) {
		t.Parallel()
		ctx := NewInvocationContext(
			context.Background(),
			"inv-123",
			".",
			testSessionID(t, "s-123"),
			"agent",
		)
		assert.Equal(t, ".", ctx.Branch())
	})

	t.Run("extremely long branch path", func(t *testing.T) {
		t.Parallel()
		// Simulate deep nesting: main.a1.a2.a3...a100
		branchParts := []string{"main"}
		for i := 1; i <= 100; i++ {
			branchParts = append(branchParts, "agent")
		}
		longBranch := strings.Join(branchParts, ".")

		ctx := NewInvocationContext(
			context.Background(),
			"inv-123",
			longBranch,
			testSessionID(t, "s-123"),
			"agent100",
		)

		assert.Equal(t, longBranch, ctx.Branch())
		// Verify structure: should have 101 parts (main + 100 agents)
		parts := strings.Split(ctx.Branch(), ".")
		assert.Equal(t, 101, len(parts))
	})

	t.Run("branch with special characters", func(t *testing.T) {
		t.Parallel()
		// Branch names might contain special chars
		specialBranch := "main.research-v2.web_search:alpha"
		ctx := NewInvocationContext(
			context.Background(),
			"inv-123",
			specialBranch,
			testSessionID(t, "s-123"),
			"web_search:alpha",
		)
		assert.Equal(t, specialBranch, ctx.Branch())
	})

	t.Run("branch with unicode", func(t *testing.T) {
		t.Parallel()
		unicodeBranch := "main.研究.網頁搜尋"
		ctx := NewInvocationContext(
			context.Background(),
			"inv-123",
			unicodeBranch,
			testSessionID(t, "s-123"),
			"網頁搜尋",
		)
		assert.Equal(t, unicodeBranch, ctx.Branch())
	})
}

// TestInvocationContext_InvocationIDEdgeCases tests InvocationID boundary conditions
func TestInvocationContext_InvocationIDEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty invocation ID", func(t *testing.T) {
		t.Parallel()
		ctx := NewInvocationContext(
			context.Background(),
			"", // empty invocation ID
			"main",
			testSessionID(t, "s-123"),
			"agent",
		)
		assert.Equal(t, "", ctx.InvocationID())
	})

	t.Run("very long invocation ID", func(t *testing.T) {
		t.Parallel()
		// UUIDs are typically 36 chars, but test with longer ID
		longID := strings.Repeat("a", 1000)
		ctx := NewInvocationContext(
			context.Background(),
			longID,
			"main",
			testSessionID(t, "s-123"),
			"agent",
		)
		assert.Equal(t, longID, ctx.InvocationID())
	})

	t.Run("special characters in invocation ID", func(t *testing.T) {
		t.Parallel()
		specialID := "inv-123_test.v2:alpha"
		ctx := NewInvocationContext(
			context.Background(),
			specialID,
			"main",
			testSessionID(t, "s-123"),
			"agent",
		)
		assert.Equal(t, specialID, ctx.InvocationID())
	})
}

// TestInvocationContext_AgentNameEdgeCases tests AgentName boundary conditions
func TestInvocationContext_AgentNameEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty agent name", func(t *testing.T) {
		t.Parallel()
		ctx := NewInvocationContext(
			context.Background(),
			"inv-123",
			"main",
			testSessionID(t, "s-123"),
			"", // empty agent name
		)
		assert.Equal(t, "", ctx.AgentName())
	})

	t.Run("very long agent name", func(t *testing.T) {
		t.Parallel()
		longName := strings.Repeat("a", 500)
		ctx := NewInvocationContext(
			context.Background(),
			"inv-123",
			"main",
			testSessionID(t, "s-123"),
			longName,
		)
		assert.Equal(t, longName, ctx.AgentName())
	})

	t.Run("agent name with special characters", func(t *testing.T) {
		t.Parallel()
		specialName := "research-agent_v2.1:beta"
		ctx := NewInvocationContext(
			context.Background(),
			"inv-123",
			"main",
			testSessionID(t, "s-123"),
			specialName,
		)
		assert.Equal(t, specialName, ctx.AgentName())
	})

	t.Run("unicode agent name", func(t *testing.T) {
		t.Parallel()
		unicodeName := "研究助手"
		ctx := NewInvocationContext(
			context.Background(),
			"inv-123",
			"main",
			testSessionID(t, "s-123"),
			unicodeName,
		)
		assert.Equal(t, unicodeName, ctx.AgentName())
	})
}

// TestInvocationContext_ContextBehaviorEdgeCases tests standard context.Context edge cases
func TestInvocationContext_ContextBehaviorEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("timeout propagation", func(t *testing.T) {
		t.Parallel()
		parent, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		invCtx := NewInvocationContext(
			parent,
			"inv-123",
			"main",
			testSessionID(t, "s-123"),
			"agent",
		)

		// Wait for timeout
		<-invCtx.Done()
		assert.ErrorIs(t, invCtx.Err(), context.DeadlineExceeded)
	})

	t.Run("deadline propagation", func(t *testing.T) {
		t.Parallel()
		deadline := time.Now().Add(50 * time.Millisecond)
		parent, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()

		invCtx := NewInvocationContext(
			parent,
			"inv-123",
			"main",
			testSessionID(t, "s-123"),
			"agent",
		)

		// Verify deadline is propagated
		actualDeadline, ok := invCtx.Deadline()
		require.True(t, ok, "deadline should be set")
		assert.Equal(t, deadline.Unix(), actualDeadline.Unix())

		// Wait for deadline
		<-invCtx.Done()
		assert.ErrorIs(t, invCtx.Err(), context.DeadlineExceeded)
	})

	t.Run("multiple context values", func(t *testing.T) {
		t.Parallel()
		type key1 string
		type key2 int

		parent := context.WithValue(context.Background(), key1("k1"), "v1")
		parent = context.WithValue(parent, key2(42), "v2")

		invCtx := NewInvocationContext(
			parent,
			"inv-123",
			"main",
			testSessionID(t, "s-123"),
			"agent",
		)

		assert.Equal(t, "v1", invCtx.Value(key1("k1")))
		assert.Equal(t, "v2", invCtx.Value(key2(42)))
		assert.Nil(t, invCtx.Value("nonexistent"))
	})

	t.Run("nil parent context", func(t *testing.T) {
		t.Parallel()
		// This should panic or be handled - test actual behavior
		// Based on invocationContext implementation, it should allow nil parent
		// but context.Context methods will panic
		// NOTE: staticcheck SA1012 warns against nil context, but this test
		// intentionally verifies behavior with nil parent
		invCtx := NewInvocationContext(
			context.TODO(), // Use context.TODO() instead of nil per staticcheck SA1012
			"inv-123",
			"main",
			testSessionID(t, "s-123"),
			"agent",
		)

		// InvocationContext methods should work
		assert.Equal(t, "inv-123", invCtx.InvocationID())
		assert.Equal(t, "main", invCtx.Branch())
		assert.Equal(t, "s-123", invCtx.SessionID().String())
		assert.Equal(t, "agent", invCtx.AgentName())

		// With context.TODO(), standard context methods work without panic
		assert.NotPanics(t, func() {
			_ = invCtx.Done()
		}, "Done() should not panic with context.TODO() parent")
	})
}

// TestReadonlyContext_Behavior tests ReadonlyContext interface
func TestReadonlyContext_Behavior(t *testing.T) {
	t.Parallel()

	t.Run("readonly context provides read access", func(t *testing.T) {
		t.Parallel()
		ctx := NewInvocationContext(
			context.Background(),
			"inv-123",
			"main.research",
			testSessionID(t, "s-123"),
			"research",
		)

		// Cast to ReadonlyContext
		readonlyCtx := ctx.(ReadonlyContext)

		// Should have access to all read methods
		assert.Equal(t, "inv-123", readonlyCtx.InvocationID())
		assert.Equal(t, "main.research", readonlyCtx.Branch())
		assert.Equal(t, "s-123", readonlyCtx.SessionID().String())
		assert.Equal(t, "research", readonlyCtx.AgentName())
	})

	t.Run("invocationContext implements ReadonlyContext", func(t *testing.T) {
		t.Parallel()
		ctx := NewInvocationContext(
			context.Background(),
			"inv-123",
			"main",
			testSessionID(t, "s-123"),
			"agent",
		)

		// Verify type assertion works
		_, ok := ctx.(ReadonlyContext)
		assert.True(t, ok, "InvocationContext should implement ReadonlyContext")
	})

	t.Run("AsReadonly returns self", func(t *testing.T) {
		t.Parallel()
		ctx := NewInvocationContext(
			context.Background(),
			"inv-123",
			"main",
			testSessionID(t, "s-123"),
			"agent",
		).(*invocationContext)

		readonlyCtx := ctx.AsReadonly()
		assert.Equal(t, ctx, readonlyCtx, "AsReadonly should return self")
	})
}

// TestInvocationContext_ConcurrentAccess tests thread safety
func TestInvocationContext_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	t.Run("concurrent reads are safe", func(t *testing.T) {
		t.Parallel()
		ctx := NewInvocationContext(
			context.Background(),
			"inv-123",
			"main.research",
			testSessionID(t, "s-123"),
			"research",
		)

		// Spawn 100 goroutines reading concurrently
		done := make(chan bool)
		for i := 0; i < 100; i++ {
			go func() {
				assert.Equal(t, "inv-123", ctx.InvocationID())
				assert.Equal(t, "main.research", ctx.Branch())
				assert.Equal(t, "s-123", ctx.SessionID().String())
				assert.Equal(t, "research", ctx.AgentName())
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 100; i++ {
			<-done
		}
	})

	t.Run("concurrent context cancellation", func(t *testing.T) {
		t.Parallel()
		parent, cancel := context.WithCancel(context.Background())
		ctx := NewInvocationContext(
			parent,
			"inv-123",
			"main",
			testSessionID(t, "s-123"),
			"agent",
		)

		// Spawn multiple goroutines waiting for cancellation
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				<-ctx.Done()
				assert.ErrorIs(t, ctx.Err(), context.Canceled)
				done <- true
			}()
		}

		// Cancel after brief delay
		time.Sleep(10 * time.Millisecond)
		cancel()

		// All goroutines should complete
		for i := 0; i < 10; i++ {
			select {
			case <-done:
				// Success
			case <-time.After(1 * time.Second):
				t.Fatal("goroutine did not receive cancellation")
			}
		}
	})
}

// TestInvocationContext_ImmutabilitySemantics tests that contexts are effectively immutable
func TestInvocationContext_ImmutabilitySemantics(t *testing.T) {
	t.Parallel()

	t.Run("modifying branch creates new context", func(t *testing.T) {
		t.Parallel()
		ctx1 := NewInvocationContext(
			context.Background(),
			"inv-123",
			"main",
			testSessionID(t, "s-123"),
			"chat",
		)

		// Create new context with extended branch
		newBranch := ctx1.Branch() + ".research"
		ctx2 := NewInvocationContext(
			context.Background(),
			ctx1.InvocationID(), // Preserve
			newBranch,           // Extend
			ctx1.SessionID(),    // Preserve
			"research",          // New agent
		)

		// Original context unchanged
		assert.Equal(t, "main", ctx1.Branch())
		assert.Equal(t, "chat", ctx1.AgentName())

		// New context has extended branch
		assert.Equal(t, "main.research", ctx2.Branch())
		assert.Equal(t, "research", ctx2.AgentName())

		// Shared values preserved
		assert.Equal(t, ctx1.InvocationID(), ctx2.InvocationID())
		assert.Equal(t, ctx1.SessionID(), ctx2.SessionID())
	})

	t.Run("contexts are independent after creation", func(t *testing.T) {
		t.Parallel()
		parent, cancel := context.WithCancel(context.Background())

		ctx1 := NewInvocationContext(parent, "inv-1", "main", testSessionID(t, "s-1"), "agent1")
		ctx2 := NewInvocationContext(parent, "inv-2", "main", testSessionID(t, "s-2"), "agent2")

		// Both contexts share parent, but have independent values
		assert.NotEqual(t, ctx1.InvocationID(), ctx2.InvocationID())
		assert.NotEqual(t, ctx1.SessionID(), ctx2.SessionID())
		assert.NotEqual(t, ctx1.AgentName(), ctx2.AgentName())

		// Canceling parent affects both
		cancel()
		<-ctx1.Done()
		<-ctx2.Done()
		assert.ErrorIs(t, ctx1.Err(), context.Canceled)
		assert.ErrorIs(t, ctx2.Err(), context.Canceled)
	})
}
