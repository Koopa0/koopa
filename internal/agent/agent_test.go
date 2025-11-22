package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/firebase/genkit/go/ai"
	// "github.com/koopa0/koopa-cli/internal/mcp" // Removed: Old MCP client
)

// ============================================================================
// Agent Execute Method Tests
// ============================================================================
// Tests in this file cover the main Agent.Execute functionality and MCP integration.
// Other tests have been organized into separate files:
//   - types_test.go: Mocks and constructor tests
//   - session_test.go: Session management tests
//   - history_test.go: History and vectorization tests
// ============================================================================

// TestExecute_ErrorHandling verifies that the Execute method correctly
// handles an error from the generator.
func TestExecute_ErrorHandling(t *testing.T) {
	// 1. Arrange
	ctx := context.Background()
	expectedErr := errors.New("API error")

	// Create a mock generator that will return an error.
	mockGen := &mockGenerator{
		Err: expectedErr,
	}

	agent := createTestAgent(t, mockGen)

	// 2. Act
	_, err := agent.Execute(ctx, "some input")

	// 3. Assert
	// We expect to receive an error.
	if err == nil {
		t.Fatal("Expected an error, but got nil")
	}

	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected error '%v', but got '%v'", expectedErr, err)
	}
}

// TestExecute_MultiTurnHistory verifies that the Execute method correctly
// manages conversation history across multiple turns.
//
// Test scenario:
// - First Execute call: verifies Generate is called
// - Second Execute call: verifies Generate is called again
// - History management is tested via HistoryLength() and ClearHistory()
//
// Note: After agent refactoring, Execute uses response.History() which filters
// to user/model messages only. The mock returns nil History() to trigger fallback path.
func TestExecute_MultiTurnHistory(t *testing.T) {
	// 1. Arrange
	ctx := context.Background()

	turnCount := 0
	mockGen := &mockGenerator{
		GenerateFunc: func(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error) {
			turnCount++
			t.Logf("Generate called for turn %d", turnCount)

			// Return simple response (History() will return nil, triggering fallback)
			return &ai.ModelResponse{
				Message: &ai.Message{
					Role:    ai.RoleModel,
					Content: []*ai.Part{ai.NewTextPart("OK")},
				},
				FinishReason: ai.FinishReasonStop,
			}, nil
		},
	}

	agent := createTestAgent(t, mockGen)

	// 2. Act - Turn 1
	t.Log("=== Turn 1: User introduces themselves ===")
	_, err := agent.Execute(ctx, "My name is Alice")
	if err != nil {
		t.Fatalf("Turn 1 error: %v", err)
	}

	// Verify Generate was called
	if turnCount != 1 {
		t.Errorf("Expected Generate to be called 1 time after turn 1, got %d", turnCount)
	}

	// 3. Act - Turn 2
	t.Log("=== Turn 2: User asks about their name ===")
	_, err = agent.Execute(ctx, "What's my name?")
	if err != nil {
		t.Fatalf("Turn 2 error: %v", err)
	}

	// 4. Assert
	// Verify Generate was called exactly twice (once per turn)
	if turnCount != 2 {
		t.Errorf("Expected Generate to be called 2 times, got %d times", turnCount)
	}

	// Verify we can clear history
	agent.ClearHistory()
	if agent.HistoryLength() != 0 {
		t.Errorf("Expected history length 0 after clear, got %d", agent.HistoryLength())
	}
}

// ============================================================================
// ConnectMCP and MCP Tests
// ============================================================================
// NOTE: Removed during Phase 2 refactoring (old MCP Client code removed)
// Phase 2 implements MCP Server (not client). Tests may be re-added if needed.

// func TestConnectMCP_NotConnected(t *testing.T) {
// 	agent := createTestAgent(t, nil)
//
// 	// Before connecting, MCP should be nil
// 	if agent.MCP() != nil {
// 		t.Error("expected MCP() to return nil before connection")
// 	}
// }
//
// func TestConnectMCP_EmptyConfig(t *testing.T) {
// 	ctx := context.Background()
// 	agent := createTestAgent(t, nil)
//
// 	// Connect with empty config should not error (or return expected error)
// 	err := agent.ConnectMCP(ctx, []mcp.Config{})
// 	// Empty config will likely error, which is expected behavior
// 	if err != nil {
// 		t.Logf("ConnectMCP with empty config returned error (expected): %v", err)
// 	}
// }
//
// func TestConnectMCP_MultipleCallsIdempotent(t *testing.T) {
// 	ctx := context.Background()
// 	agent := createTestAgent(t, nil)
//
// 	// Call ConnectMCP multiple times - should only execute once due to sync.Once
// 	err1 := agent.ConnectMCP(ctx, []mcp.Config{})
// 	err2 := agent.ConnectMCP(ctx, []mcp.Config{})
//
// 	// Both calls should return the same error (if any) due to sync.Once
// 	if (err1 == nil) != (err2 == nil) {
// 		t.Errorf("multiple ConnectMCP calls returned different error states: err1=%v, err2=%v", err1, err2)
// 	}
// }
//
// func TestMCP_Getter(t *testing.T) {
// 	agent := createTestAgent(t, nil)
//
// 	// Test getter returns nil initially (before connection)
// 	mcpServer := agent.MCP()
// 	if mcpServer != nil {
// 		t.Error("expected MCP() to return nil initially")
// 	}
// }

// ============================================================================
// tools Function Tests
// ============================================================================

func TestTools_WithoutMCP(t *testing.T) {
	ctx := context.Background()
	agent := createTestAgent(t, nil)

	// Get tools without MCP connection
	toolRefs := agent.tools(ctx)

	// Should return at least some local tools
	if len(toolRefs) == 0 {
		t.Error("expected tools() to return local tools, got empty slice")
	}

	t.Logf("tools() returned %d tool(s) without MCP", len(toolRefs))
}

// NOTE: Removed during Phase 2 refactoring (old MCP Client code removed)
// func TestTools_WithMCP(t *testing.T) {
// 	ctx := context.Background()
// 	agent := createTestAgent(t, nil)
//
// 	// Attempt to connect MCP (will likely fail with empty config, but that's ok)
// 	_ = agent.ConnectMCP(ctx, []mcp.Config{})
//
// 	// Get tools - should handle both success and failure of MCP connection gracefully
// 	toolRefs := agent.tools(ctx)
//
// 	// Should return local tools at minimum (even if MCP connection failed)
// 	if len(toolRefs) == 0 {
// 		t.Error("expected tools() to return at least local tools")
// 	}
//
// 	t.Logf("tools() returned %d tool(s) with MCP connection attempt", len(toolRefs))
// }

// ============================================================================
// Phase 3: Tool Registry Separation Tests
// ============================================================================

// TestAgent_Tools_LocalOnly tests that tools() returns only local tools
func TestAgent_Tools_LocalOnly(t *testing.T) {
	ctx := context.Background()
	agent := createTestAgent(t, nil)

	// Get local tools
	localTools := agent.tools(ctx)

	// Should have at least some local tools
	if len(localTools) == 0 {
		t.Error("expected at least some local tools, got 0")
	}

	t.Logf("tools() returned %d local tools", len(localTools))
}

// NOTE: Removed during Phase 2 refactoring (old MCP Client code removed)
// Phase 2 no longer has mcpTools() method (MCP Server doesn't use this pattern)
// func TestAgent_MCPTools_NotConnected(t *testing.T) {
// 	ctx := context.Background()
// 	agent := createTestAgent(t, nil)
//
// 	// Get MCP tools (should be nil/empty when not connected)
// 	mcpTools := agent.mcpTools(ctx)
//
// 	if len(mcpTools) != 0 {
// 		t.Errorf("expected 0 MCP tools when not connected, got %d", len(mcpTools))
// 	}
//
// 	t.Log("mcpTools() correctly returned empty slice when not connected")
// }

// TestAgent_AllTools_Aggregation tests that allTools() returns local tools only
// NOTE: Modified for Phase 2 - no longer aggregates MCP tools (MCP Client removed)
func TestAgent_AllTools_Aggregation(t *testing.T) {
	ctx := context.Background()
	agent := createTestAgent(t, nil)

	// Get counts
	localCount := len(agent.tools(ctx))
	allCount := len(agent.allTools(ctx))

	// allTools should equal local tools only (no MCP client)
	if allCount != localCount {
		t.Errorf("allTools() = %d, expected %d (local tools only)",
			allCount, localCount)
	}

	t.Logf("allTools() correctly returned local tools: total=%d", allCount)
}

// NOTE: Removed during Phase 2 refactoring (old MCP Client code removed)
// func TestAgent_MCPConnection_ToolsUpdate(t *testing.T) {
// 	ctx := context.Background()
// 	agent := createTestAgent(t, nil)
//
// 	// Before MCP connection
// 	beforeLocal := len(agent.tools(ctx))
// 	beforeMCP := len(agent.mcpTools(ctx))
// 	beforeAll := len(agent.allTools(ctx))
//
// 	// Connect MCP (will likely fail with empty config, but that's ok for this test)
// 	_ = agent.ConnectMCP(ctx, []mcp.Config{})
//
// 	// After MCP connection attempt
// 	afterLocal := len(agent.tools(ctx))
// 	afterMCP := len(agent.mcpTools(ctx))
// 	afterAll := len(agent.allTools(ctx))
//
// 	// Local tools should not change
// 	if afterLocal != beforeLocal {
// 		t.Errorf("local tools changed after MCP connection: before=%d, after=%d",
// 			beforeLocal, afterLocal)
// 	}
//
// 	t.Logf("Local tools: %d (unchanged)", afterLocal)
// 	t.Logf("MCP tools: before=%d, after=%d", beforeMCP, afterMCP)
// 	t.Logf("All tools: before=%d, after=%d", beforeAll, afterAll)
// }

// TestAgent_Kit_NotNil tests that kit is initialized (Phase 1: Kit replaces Registry)
func TestAgent_Kit_NotNil(t *testing.T) {
	agent := createTestAgent(t, nil)

	if agent.kit == nil {
		t.Fatal("kit should be initialized")
	}

	t.Log("kit correctly initialized")
}
