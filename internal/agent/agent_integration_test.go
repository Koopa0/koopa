//go:build integration
// +build integration

package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// waitForCondition polls until condition is met or timeout.
// This replaces brittle time.Sleep calls with robust polling.
func waitForCondition(t *testing.T, timeout time.Duration, check func() bool, msg string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.Fatalf("Timeout waiting for: %s", msg)
		case <-ticker.C:
			if check() {
				return
			}
		}
	}
}

// TestAgent_SimpleConversation_Integration tests basic conversation flow
func TestAgent_SimpleConversation_Integration(t *testing.T) {
	framework, cleanup := SetupTestAgent(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Execute simple query (synchronous)
	resp, err := framework.Agent.Execute(ctx, "What is 2+2? Answer in one word.")

	// Assertions
	require.NoError(t, err, "Should not have error")
	require.NotNil(t, resp, "Response should not be nil")

	t.Logf("Agent response: %s", resp.FinalText)
	assert.NotEmpty(t, resp.FinalText, "Response should not be empty")

	// Verify history was updated
	assert.Equal(t, 2, framework.Agent.HistoryLength(), "Should have user + model messages")
}

// TestAgent_MultiTurnConversation_Integration tests multi-turn conversation
func TestAgent_MultiTurnConversation_Integration(t *testing.T) {
	framework, cleanup := SetupTestAgent(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Turn 1: Ask about a topic (synchronous)
	resp1, err := framework.Agent.Execute(ctx, "My favorite color is blue.")
	require.NoError(t, err)
	require.NotNil(t, resp1)

	// Turn 2: Ask follow-up question (synchronous)
	resp2, err := framework.Agent.Execute(ctx, "What is my favorite color?")
	require.NoError(t, err)
	require.NotNil(t, resp2)

	t.Logf("Agent response to follow-up: %s", resp2.FinalText)

	// Verify agent remembered previous context
	assert.Contains(t, strings.ToLower(resp2.FinalText), "blue", "Agent should remember favorite color")

	// Verify history length (2 turns = 4 messages: user1, model1, user2, model2)
	assert.Equal(t, 4, framework.Agent.HistoryLength(), "Should have 4 messages after 2 turns")
}

// TestAgent_StreamingResponse_Integration tests streaming text chunks
func TestAgent_StreamingResponse_Integration(t *testing.T) {
	framework, cleanup := SetupTestAgent(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Ask for a longer response (synchronous execution, no streaming)
	resp, err := framework.Agent.Execute(ctx, "Count from 1 to 5.")
	require.NoError(t, err)
	require.NotNil(t, resp)

	t.Logf("Response: %s", resp.FinalText)
	assert.NotEmpty(t, resp.FinalText, "Response should not be empty")
}

// TestAgent_RAGRetrieval_Integration tests RAG knowledge retrieval
func TestAgent_RAGRetrieval_Integration(t *testing.T) {
	framework, cleanup := SetupTestAgent(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Index system knowledge first
	framework.IndexSystemKnowledge(t)

	// Also add a custom document
	customDoc := knowledge.Document{
		ID:      "test-koopa-info",
		Content: "Koopa is a terminal-based AI assistant built with Firebase Genkit in Go. It features RAG, tool calling, and session management.",
		Metadata: map[string]string{
			"source_type": "test",
			"topic":       "koopa",
		},
	}
	err := framework.KnowledgeStore.Add(ctx, customDoc)
	require.NoError(t, err, "Should index custom document")

	// Query about Koopa (should trigger RAG, synchronous)
	resp, err := framework.Agent.Execute(ctx, "What is Koopa?")
	require.NoError(t, err)
	require.NotNil(t, resp)

	t.Logf("RAG-enhanced response: %s", resp.FinalText)

	// Verify response contains information from our indexed document
	// The response should mention key terms from the indexed content
	responseLower := strings.ToLower(resp.FinalText)
	assert.True(t,
		strings.Contains(responseLower, "assistant") ||
			strings.Contains(responseLower, "terminal") ||
			strings.Contains(responseLower, "genkit"),
		"Response should contain information from RAG context")
}

// TestAgent_SessionPersistence_Integration tests session message persistence
func TestAgent_SessionPersistence_Integration(t *testing.T) {
	framework, cleanup := SetupTestAgent(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a new session
	sess, err := framework.Agent.NewSession(ctx, "Persistence Test")
	require.NoError(t, err)
	sessionID := sess.ID

	// Execute conversation in this session
	err = framework.Agent.SwitchSession(ctx, sessionID)
	require.NoError(t, err)

	resp, err := framework.Agent.Execute(ctx, "Hello, my name is Alice.")
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Wait for async persistence using polling
	// Enhanced: Check for specific roles, not just count
	waitForCondition(t, 2*time.Second, func() bool {
		messages, err := framework.SessionStore.GetMessages(ctx, sessionID, 10, 0)
		if err != nil {
			t.Logf("Polling: GetMessages failed: %v", err)
			return false
		}
		if len(messages) < 2 {
			t.Logf("Polling: Expected >= 2 messages, got %d", len(messages))
			return false
		}
		// Verify roles to ensure correct persistence
		hasUser := messages[0].Role == "user"
		hasModel := messages[1].Role == "model"
		if !hasUser || !hasModel {
			t.Logf("Polling: Incorrect roles - msg[0]=%s, msg[1]=%s", messages[0].Role, messages[1].Role)
			return false
		}
		return true
	}, "message persistence with correct roles")

	// Verify messages were persisted to database
	messages, err := framework.SessionStore.GetMessages(ctx, sessionID, 10, 0)
	require.NoError(t, err)

	// Should have at least 2 messages: user message + model response
	assert.GreaterOrEqual(t, len(messages), 2, "Should have persisted messages")

	// Verify first message is user message
	assert.Equal(t, "user", messages[0].Role, "First message should be from user")

	// Verify second message is model response
	assert.Equal(t, "model", messages[1].Role, "Second message should be from model")
}

// TestAgent_ErrorHandling_Integration tests error scenarios
func TestAgent_ErrorHandling_Integration(t *testing.T) {
	framework, cleanup := SetupTestAgent(t)
	defer cleanup()

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := framework.Agent.Execute(ctx, "This should fail due to cancelled context")

	// Should receive an error due to cancelled context
	assert.Error(t, err, "Should receive error for cancelled context")
	t.Logf("Received expected error: %v", err)
}

// TestAgent_ClearHistory_Integration tests history clearing
func TestAgent_ClearHistory_Integration(t *testing.T) {
	framework, cleanup := SetupTestAgent(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Build up some history
	resp1, err := framework.Agent.Execute(ctx, "Remember this: my lucky number is 7")
	require.NoError(t, err)
	require.NotNil(t, resp1)

	assert.Equal(t, 2, framework.Agent.HistoryLength(), "Should have 2 messages")

	// Clear history
	framework.Agent.ClearHistory()
	assert.Equal(t, 0, framework.Agent.HistoryLength(), "History should be cleared")

	// Verify agent doesn't remember previous context
	resp2, err := framework.Agent.Execute(ctx, "What is my lucky number?")
	require.NoError(t, err)
	require.NotNil(t, resp2)

	t.Logf("Response after clearing history: %s", resp2.FinalText)

	// Agent should not know the lucky number anymore
	assert.NotEmpty(t, resp2.FinalText, "Should receive a response")
	// Verify agent forgot the number (enhanced verification)
	assert.NotContains(t, resp2.FinalText, "7", "Agent should not remember the lucky number after history is cleared")
}
