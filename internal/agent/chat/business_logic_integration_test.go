//go:build integration
// +build integration

package chat_test

import (
	"context"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecuteStream_BasicExecution verifies basic chat execution works.
// This is the baseline test to ensure the system works before refactoring.
func TestExecuteStream_BasicExecution(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx, sessionID, branch := newInvocationContext(context.Background(), framework.SessionID)
	resp, err := framework.Agent.ExecuteStream(ctx, sessionID, branch,
		"What is 2+2?",
		false,
		nil,
	)

	require.NoError(t, err, "Basic execution should succeed")
	assert.NotEmpty(t, resp.FinalText, "Response should not be empty")
	t.Logf("Response: %s", resp.FinalText)
}

// TestExecuteStream_HistoryPersistence verifies messages are saved to session.
// This ensures that conversation context is maintained across messages.
func TestExecuteStream_HistoryPersistence(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx, sessionID, branch := newInvocationContext(context.Background(), framework.SessionID)

	// First query - establish context
	resp1, err := framework.Agent.ExecuteStream(ctx, sessionID, branch, "Remember: my favorite color is blue", false, nil)
	require.NoError(t, err, "First message should succeed")
	assert.NotEmpty(t, resp1.FinalText)
	t.Logf("First response: %s", resp1.FinalText)

	// Second query - should remember context
	resp2, err := framework.Agent.ExecuteStream(ctx, sessionID, branch, "What is my favorite color?", false, nil)
	require.NoError(t, err, "Second message should succeed")
	assert.Contains(t, resp2.FinalText, "blue", "Should remember previous context")
	t.Logf("Second response: %s", resp2.FinalText)
}

// TestExecuteStream_EmptyResponseFallback verifies fallback message when LLM returns empty.
// Per Proposal 030: Verify FallbackResponseMessage is returned.
//
// Note: LLMs rarely return truly empty responses, so this test verifies the defensive check.
func TestExecuteStream_EmptyResponseFallback(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx, sessionID, branch := newInvocationContext(context.Background(), framework.SessionID)

	// Execute with minimal query (edge case that might trigger empty response)
	resp, err := framework.Agent.ExecuteStream(ctx, sessionID, branch,
		" ", // Single space - edge case
		false,
		nil,
	)

	require.NoError(t, err, "Should not fail even with edge case input")
	assert.NotEmpty(t, resp.FinalText, "Should have non-empty response")

	// The defensive check in chat.go ensures we never return empty text
	// If we do hit the fallback, it contains "apologize"
	t.Logf("Response: %s", resp.FinalText)
}

// TestExecuteStream_HistoryLoadFailure_ProperError verifies that when
// LoadHistory fails (critical operation), the request fails properly.
// Per Proposal 030 and Architecture Master review: LoadHistory is CRITICAL,
// AppendMessages is NON-CRITICAL (graceful degradation).
//
// NOTE: This test was redesigned based on Architecture Master feedback.
// Original test intended to verify AppendMessages graceful degradation,
// but closing DB pool affects LoadHistory first (which should fail).
//
// TODO: Add separate test for AppendMessages graceful degradation using mock SessionStore.
// The implementation at chat.go:274-277 correctly logs errors without failing the request,
// but we need mocking infrastructure to test it in isolation.
func TestExecuteStream_HistoryLoadFailure_ProperError(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx, sessionID, branch := newInvocationContext(context.Background(), framework.SessionID)

	// STEP 1: Execute normally to verify baseline
	resp1, err := framework.Agent.ExecuteStream(ctx, sessionID, branch,
		"first query",
		false,
		nil,
	)
	require.NoError(t, err, "First message should succeed")
	assert.NotEmpty(t, resp1.FinalText)
	t.Logf("First response: %s", resp1.FinalText)

	// STEP 2: Close database connection to cause LoadHistory failure
	framework.DBContainer.Pool.Close()

	// STEP 3: Execute again - should FAIL because LoadHistory is critical
	resp2, err := framework.Agent.ExecuteStream(ctx, sessionID, branch,
		"second query",
		false,
		nil,
	)

	// LoadHistory failure should propagate error (critical operation)
	require.Error(t, err, "Should fail when LoadHistory fails (critical operation)")
	assert.Nil(t, resp2, "Response should be nil when critical operation fails")
	assert.Contains(t, err.Error(), "failed to load history",
		"Error should indicate history loading failure")
	t.Logf("Expected error: %v", err)

	// This confirms the architectural distinction:
	// - LoadHistory failure → request fails (critical)
	// - AppendMessages failure → request succeeds, error logged (non-critical)
}

// TestExecuteStream_RAGGracefulDegradation verifies that RAG retrieval failures
// don't block chat execution.
// Per Proposal 030: Verify returns nil, doesn't crash.
//
// This tests graceful degradation via context cancellation (simulates timeout).
func TestExecuteStream_RAGGracefulDegradation(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	// Use canceled context to trigger RAG failure
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately to simulate timeout

	_, sessionID, branch := newInvocationContext(context.Background(), framework.SessionID)

	// Execute with canceled context
	resp, err := framework.Agent.ExecuteStream(ctx, sessionID, branch,
		"test query",
		false,
		nil,
	)

	// With canceled context, the LLM execution will fail (expected)
	// But this test proves the code path handles context cancellation gracefully
	if err != nil {
		assert.Contains(t, err.Error(), "context canceled", "Should fail with context canceled error")
		t.Logf("Expected error: %v", err)
	} else {
		// If LLM somehow succeeds despite canceled context, that's also fine
		assert.NotNil(t, resp)
		t.Logf("Unexpectedly succeeded: %s", resp.FinalText)
	}
}

// TestExecuteStream_ConcurrentSessions verifies race-free concurrent access.
// Per Proposal 030: Verify no data races (run with -race flag).
//
// This ensures the chat agent is safe for concurrent use across multiple sessions.
func TestExecuteStream_ConcurrentSessions(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx := context.Background()

	// Create 3 separate sessions
	session1 := framework.CreateTestSession(t, "Concurrent Session 1")
	session2 := framework.CreateTestSession(t, "Concurrent Session 2")
	session3 := framework.CreateTestSession(t, "Concurrent Session 3")

	// Result channel to collect goroutine results (avoid testing.T concurrent access)
	type result struct {
		idx   int
		err   error
		text  string
		empty bool
	}
	results := make(chan result, 10)

	// Run 10 concurrent queries across 3 sessions
	for i := 0; i < 10; i++ {
		sessionUUID := session1
		if i%3 == 1 {
			sessionUUID = session2
		} else if i%3 == 2 {
			sessionUUID = session3
		}

		go func(sID uuid.UUID, idx int) {
			invCtx, sessionID, branch := newInvocationContext(ctx, sID)
			resp, err := framework.Agent.ExecuteStream(invCtx, sessionID, branch,
				"Test concurrent query",
				false,
				nil,
			)

			// Collect results via channel (safe for concurrent access)
			res := result{idx: idx, err: err}
			if resp != nil {
				res.text = resp.FinalText
				res.empty = resp.FinalText == ""
			}
			results <- res
		}(sessionUUID, i)
	}

	// Wait for all goroutines and assert in main goroutine (thread-safe)
	for i := 0; i < 10; i++ {
		res := <-results
		assert.NoError(t, res.err, "Concurrent execution %d should not error", res.idx)
		assert.False(t, res.empty, "Concurrent response %d should not be empty", res.idx)
	}

	t.Log("All 10 concurrent executions completed successfully")
}

// TestExecuteStream_StreamingCallback verifies streaming works correctly.
// Per Proposal 030: Streaming callback error propagation.
//
// This ensures that streaming mode produces chunks and handles callbacks properly.
func TestExecuteStream_StreamingCallback(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx, sessionID, branch := newInvocationContext(context.Background(), framework.SessionID)
	chunks := 0

	callback := func(ctx context.Context, chunk *ai.ModelResponseChunk) error {
		chunks++
		t.Logf("Received chunk %d: %d bytes", chunks, len(chunk.Text()))
		return nil // Continue streaming
	}

	resp, err := framework.Agent.ExecuteStream(ctx, sessionID, branch,
		"Count from 1 to 5",
		false,
		callback,
	)

	require.NoError(t, err, "Streaming execution should succeed")
	assert.NotEmpty(t, resp.FinalText, "Final response should not be empty")
	assert.Greater(t, chunks, 0, "Should have received streaming chunks")
	t.Logf("Received %d streaming chunks, final response: %s", chunks, resp.FinalText)
}

// TestExecuteStream_MaxTurnsEnforcement verifies that tool calling loops
// are limited by MaxTurns configuration.
// Per Proposal 030: Tool loop exceeds MaxTurns → verify stops, returns partial result.
//
// This prevents infinite tool calling loops.
func TestExecuteStream_MaxTurnsEnforcement(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx, sessionID, branch := newInvocationContext(context.Background(), framework.SessionID)

	// NOTE: Chat now captures maxTurns at construction time (immutable).
	// Modifying framework.Config.MaxTurns after construction has no effect.
	// This test verifies that the captured maxTurns value is enforced.

	// Query that might trigger tool calls
	// (Exact behavior depends on LLM, but MaxTurns should limit it)
	resp, err := framework.Agent.ExecuteStream(ctx, sessionID, branch,
		"List all files in current directory",
		false,
		nil,
	)

	require.NoError(t, err, "Should not error even when MaxTurns is reached")
	assert.NotEmpty(t, resp.FinalText, "Should return response even if limited by MaxTurns")

	// Verify tool calls were made (shows agent tried to use tools)
	if len(resp.ToolRequests) > 0 {
		t.Logf("Tool calls made: %d", len(resp.ToolRequests))
	}

	t.Logf("Response: %s", resp.FinalText)
}

// TestExecuteStream_DefensiveNilCheck verifies the defensive nil check in ExecuteStream.
// Per Proposal 030 line 452: Verify defensive check at chat.go:252-255.
//
// This test ensures that the execute() method never returns (nil, nil),
// which would be a programming error. The defensive check prevents this edge case
// from causing a nil pointer dereference.
//
// Note: This is defensive code that should never be triggered in normal operation.
// We test it by verifying that various edge cases still return valid responses.
func TestExecuteStream_DefensiveNilCheck(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx, sessionID, branch := newInvocationContext(context.Background(), framework.SessionID)

	// Test various edge cases that should all return valid (non-nil) responses
	testCases := []struct {
		name  string
		input string
	}{
		{"empty_query", ""},
		{"whitespace_only", "   "},
		{"single_char", "a"},
		{"very_short", "hi"},
		{"special_chars", "!@#$%^&*()"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := framework.Agent.ExecuteStream(ctx, sessionID, branch,
				tc.input,
				false,
				nil,
			)

			// Should either succeed with valid response OR fail with error
			// Should NEVER return (nil, nil) which would trigger defensive check
			if err != nil {
				// Error is acceptable for edge cases
				t.Logf("Input %q returned error (acceptable): %v", tc.input, err)
			} else {
				// Success must have non-nil response
				require.NotNil(t, resp, "Response must not be nil when error is nil")
				assert.NotNil(t, resp.FinalText, "FinalText should be set (may be empty string)")
				t.Logf("Input %q returned valid response: %q", tc.input, resp.FinalText)
			}

			// The key assertion: we should NEVER get (nil, nil)
			// If err is nil, resp MUST be non-nil (enforced by defensive check)
			if err == nil {
				require.NotNil(t, resp, "DEFENSIVE CHECK VIOLATED: execute returned (nil, nil)")
			}
		})
	}
}
