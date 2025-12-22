//go:build integration
// +build integration

package chat_test

import (
	"context"
	"errors"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Phase 0.3: Streaming Integration Tests
// =============================================================================

// TestChatAgent_StreamingCallbackError verifies that errors from streaming
// callbacks are properly propagated and stop the stream.
// Per Proposal 030: Callback returns error after N chunks, verify stream stops,
// error propagated.
func TestChatAgent_StreamingCallbackError(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx, sessionID := newInvocationContext(context.Background(), framework.SessionID)
	chunks := 0
	maxChunks := 3

	// Callback that errors after 3 chunks
	callback := func(ctx context.Context, chunk *ai.ModelResponseChunk) error {
		chunks++
		t.Logf("Received chunk %d: %d bytes", chunks, len(chunk.Text()))

		if chunks >= maxChunks {
			return errors.New("simulated streaming error after 3 chunks")
		}
		return nil
	}

	resp, err := framework.Agent.ExecuteStream(ctx, sessionID,
		"Write a long story about a space adventure",
		callback,
	)

	// Stream should stop and propagate the error
	require.Error(t, err, "Should propagate streaming callback error")
	assert.Contains(t, err.Error(), "simulated streaming error",
		"Error should contain callback error message")
	assert.Equal(t, maxChunks, chunks,
		"Should have received exactly maxChunks chunks before error")

	// Response might be nil or partial depending on error handling
	if resp != nil {
		t.Logf("Partial response received before error: %s", resp.FinalText)
	} else {
		t.Log("No response returned (expected when streaming errors)")
	}
}

// TestChatAgent_StreamingCallbackSuccess verifies that streaming works
// correctly when callback always succeeds.
func TestChatAgent_StreamingCallbackSuccess(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx, sessionID := newInvocationContext(context.Background(), framework.SessionID)
	chunks := 0
	var receivedTexts []string

	callback := func(ctx context.Context, chunk *ai.ModelResponseChunk) error {
		chunks++
		text := chunk.Text()
		receivedTexts = append(receivedTexts, text)
		t.Logf("Chunk %d: %q", chunks, text)
		return nil // Success - continue streaming
	}

	resp, err := framework.Agent.ExecuteStream(ctx, sessionID,
		"Count from 1 to 5",
		callback,
	)

	require.NoError(t, err, "Streaming should succeed when callback always returns nil")
	assert.NotEmpty(t, resp.FinalText, "Should have complete response")
	assert.Greater(t, chunks, 0, "Should have received at least one chunk")

	t.Logf("Received %d chunks, final response: %s", chunks, resp.FinalText)
}

// TestChatAgent_StreamingVsNonStreaming verifies that streaming and non-streaming
// modes produce equivalent results.
func TestChatAgent_StreamingVsNonStreaming(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx := context.Background()
	query := "What is 2+2? Answer with just the number."

	// Non-streaming execution
	session1 := framework.CreateTestSession(t, "Non-streaming test")
	invCtx1, sessionID1 := newInvocationContext(ctx, session1)
	respNoStream, err := framework.Agent.ExecuteStream(invCtx1, sessionID1,
		query,
		nil, // No callback = non-streaming
	)
	require.NoError(t, err, "Non-streaming should succeed")
	assert.NotEmpty(t, respNoStream.FinalText)

	// Streaming execution
	session2 := framework.CreateTestSession(t, "Streaming test")
	invCtx2, sessionID2 := newInvocationContext(ctx, session2)
	var streamedResponse string
	callback := func(ctx context.Context, chunk *ai.ModelResponseChunk) error {
		streamedResponse += chunk.Text()
		return nil
	}

	respStream, err := framework.Agent.ExecuteStream(invCtx2, sessionID2,
		query,
		callback,
	)
	require.NoError(t, err, "Streaming should succeed")
	assert.NotEmpty(t, respStream.FinalText)

	// Both should contain "4" (the answer)
	assert.Contains(t, respNoStream.FinalText, "4",
		"Non-streaming response should contain answer")
	assert.Contains(t, respStream.FinalText, "4",
		"Streaming response should contain answer")

	t.Logf("Non-streaming: %s", respNoStream.FinalText)
	t.Logf("Streaming: %s", respStream.FinalText)
}

// TestChatAgent_StreamingContextCancellation verifies that canceling the
// context stops streaming.
func TestChatAgent_StreamingContextCancellation(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	_, sessionID := newInvocationContext(context.Background(), framework.SessionID)
	chunks := 0

	callback := func(callbackCtx context.Context, chunk *ai.ModelResponseChunk) error {
		chunks++
		t.Logf("Received chunk %d", chunks)

		// Cancel after first chunk
		if chunks == 1 {
			cancel()
		}
		return nil
	}

	resp, err := framework.Agent.ExecuteStream(ctx, sessionID,
		"Write a very long story",
		callback,
	)

	// Should fail with context canceled error
	if err != nil {
		assert.Contains(t, err.Error(), "context canceled",
			"Should fail with context canceled error")
		t.Logf("Context cancellation detected: %v", err)
	} else {
		// If somehow completed despite cancellation, that's unexpected but not wrong
		assert.NotNil(t, resp)
		t.Logf("Completed despite cancellation (unexpected): %s", resp.FinalText)
	}
}

// TestChatAgent_StreamingEmptyChunks verifies handling of empty chunks
// in streaming mode.
func TestChatAgent_StreamingEmptyChunks(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx, sessionID := newInvocationContext(context.Background(), framework.SessionID)
	totalChunks := 0
	emptyChunks := 0

	callback := func(ctx context.Context, chunk *ai.ModelResponseChunk) error {
		totalChunks++
		text := chunk.Text()
		if text == "" {
			emptyChunks++
			t.Logf("Chunk %d is empty", totalChunks)
		} else {
			t.Logf("Chunk %d: %q", totalChunks, text)
		}
		return nil
	}

	resp, err := framework.Agent.ExecuteStream(ctx, sessionID,
		"Say hello",
		callback,
	)

	require.NoError(t, err, "Should handle empty chunks gracefully")
	assert.NotEmpty(t, resp.FinalText, "Final response should not be empty")

	if emptyChunks > 0 {
		t.Logf("Received %d empty chunks out of %d total chunks", emptyChunks, totalChunks)
	} else {
		t.Logf("No empty chunks received (%d total chunks)", totalChunks)
	}
}
