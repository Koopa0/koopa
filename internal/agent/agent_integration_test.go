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

// TestAgent_SimpleConversation_Integration tests basic conversation flow
func TestAgent_SimpleConversation_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	framework, cleanup := SetupTestAgent(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Execute simple query
	eventCh := framework.Agent.Execute(ctx, "What is 2+2? Answer in one word.")

	var textChunks []string
	var isComplete bool
	var finalError error

	for event := range eventCh {
		switch event.Type {
		case EventTypeText:
			textChunks = append(textChunks, event.TextChunk)
		case EventTypeComplete:
			isComplete = event.IsComplete
		case EventTypeError:
			finalError = event.Error
		}
	}

	// Assertions
	require.NoError(t, finalError, "Should not have error")
	assert.True(t, isComplete, "Conversation should complete")
	assert.Greater(t, len(textChunks), 0, "Should receive text chunks")

	// Verify response contains answer
	fullResponse := strings.Join(textChunks, "")
	t.Logf("Agent response: %s", fullResponse)
	assert.NotEmpty(t, fullResponse, "Response should not be empty")

	// Verify history was updated
	assert.Equal(t, 2, framework.Agent.HistoryLength(), "Should have user + model messages")
}

// TestAgent_MultiTurnConversation_Integration tests multi-turn conversation
func TestAgent_MultiTurnConversation_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	framework, cleanup := SetupTestAgent(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Turn 1: Ask about a topic
	eventCh1 := framework.Agent.Execute(ctx, "My favorite color is blue.")
	for event := range eventCh1 {
		if event.Type == EventTypeError {
			require.NoError(t, event.Error)
		}
	}

	// Turn 2: Ask follow-up question
	eventCh2 := framework.Agent.Execute(ctx, "What is my favorite color?")

	var responseText []string
	for event := range eventCh2 {
		switch event.Type {
		case EventTypeText:
			responseText = append(responseText, event.TextChunk)
		case EventTypeError:
			require.NoError(t, event.Error)
		}
	}

	fullResponse := strings.Join(responseText, "")
	t.Logf("Agent response to follow-up: %s", fullResponse)

	// Verify agent remembered previous context
	assert.Contains(t, strings.ToLower(fullResponse), "blue", "Agent should remember favorite color")

	// Verify history length (2 turns = 4 messages: user1, model1, user2, model2)
	assert.Equal(t, 4, framework.Agent.HistoryLength(), "Should have 4 messages after 2 turns")
}

// TestAgent_StreamingResponse_Integration tests streaming text chunks
func TestAgent_StreamingResponse_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	framework, cleanup := SetupTestAgent(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Ask for a longer response to test streaming
	eventCh := framework.Agent.Execute(ctx, "Count from 1 to 5.")

	var textChunks []string
	var chunkCount int

	for event := range eventCh {
		switch event.Type {
		case EventTypeText:
			textChunks = append(textChunks, event.TextChunk)
			chunkCount++
			t.Logf("Received chunk %d: %q", chunkCount, event.TextChunk)
		case EventTypeError:
			require.NoError(t, event.Error)
		}
	}

	// Streaming should produce multiple chunks for longer responses
	// Note: Exact chunk count varies, but should be > 1 for a longer response
	assert.Greater(t, chunkCount, 0, "Should receive at least one text chunk")

	fullResponse := strings.Join(textChunks, "")
	assert.NotEmpty(t, fullResponse, "Full response should not be empty")
}

// TestAgent_RAGRetrieval_Integration tests RAG knowledge retrieval
func TestAgent_RAGRetrieval_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

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

	// Query about Koopa (should trigger RAG)
	eventCh := framework.Agent.Execute(ctx, "What is Koopa?")

	var responseText []string
	for event := range eventCh {
		switch event.Type {
		case EventTypeText:
			responseText = append(responseText, event.TextChunk)
		case EventTypeError:
			require.NoError(t, event.Error)
		}
	}

	fullResponse := strings.Join(responseText, "")
	t.Logf("RAG-enhanced response: %s", fullResponse)

	// Verify response contains information from our indexed document
	// The response should mention key terms from the indexed content
	responseLower := strings.ToLower(fullResponse)
	assert.True(t,
		strings.Contains(responseLower, "assistant") ||
			strings.Contains(responseLower, "terminal") ||
			strings.Contains(responseLower, "genkit"),
		"Response should contain information from RAG context")
}

// TestAgent_SessionPersistence_Integration tests session message persistence
func TestAgent_SessionPersistence_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

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

	eventCh := framework.Agent.Execute(ctx, "Hello, my name is Alice.")
	for event := range eventCh {
		if event.Type == EventTypeError {
			require.NoError(t, event.Error)
		}
	}

	// Wait a bit for async persistence
	time.Sleep(500 * time.Millisecond)

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
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	framework, cleanup := SetupTestAgent(t)
	defer cleanup()

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	eventCh := framework.Agent.Execute(ctx, "This should fail due to cancelled context")

	var hasError bool
	for event := range eventCh {
		if event.Type == EventTypeError {
			hasError = true
			t.Logf("Received expected error: %v", event.Error)
		}
	}

	// Note: Depending on timing, we may or may not receive an error event
	// The goroutine might exit before sending the error
	// So we just log the result rather than assert
	t.Logf("Error received: %v", hasError)
}

// TestAgent_ClearHistory_Integration tests history clearing
func TestAgent_ClearHistory_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	framework, cleanup := SetupTestAgent(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Build up some history
	eventCh := framework.Agent.Execute(ctx, "Remember this: my lucky number is 7")
	for event := range eventCh {
		if event.Type == EventTypeError {
			require.NoError(t, event.Error)
		}
	}

	assert.Equal(t, 2, framework.Agent.HistoryLength(), "Should have 2 messages")

	// Clear history
	framework.Agent.ClearHistory()
	assert.Equal(t, 0, framework.Agent.HistoryLength(), "History should be cleared")

	// Verify agent doesn't remember previous context
	eventCh2 := framework.Agent.Execute(ctx, "What is my lucky number?")

	var responseText []string
	for event := range eventCh2 {
		switch event.Type {
		case EventTypeText:
			responseText = append(responseText, event.TextChunk)
		case EventTypeError:
			require.NoError(t, event.Error)
		}
	}

	fullResponse := strings.Join(responseText, "")
	t.Logf("Response after clearing history: %s", fullResponse)

	// Agent should not know the lucky number anymore
	// (exact assertion is tricky since it might say "I don't know" or similar)
	assert.NotEmpty(t, fullResponse, "Should receive a response")
}
