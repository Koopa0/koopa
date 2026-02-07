//go:build integration
// +build integration

package chat_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/firebase/genkit/go/ai"
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
	if err == nil {
		t.Fatal("ExecuteStream() expected error, got nil (should propagate streaming callback error)")
	}
	if !strings.Contains(err.Error(), "simulated streaming error") {
		t.Errorf("ExecuteStream() error = %q, want to contain %q", err.Error(), "simulated streaming error")
	}
	if chunks != maxChunks {
		t.Errorf("chunks received = %d, want %d (should have received exactly maxChunks chunks before error)", chunks, maxChunks)
	}

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

	if err != nil {
		t.Fatalf("ExecuteStream() unexpected error: %v (streaming should succeed when callback always returns nil)", err)
	}
	if resp == nil {
		t.Fatal("ExecuteStream() response is nil, want non-nil when error is nil")
	}
	if resp.FinalText == "" {
		t.Error("ExecuteStream() response.FinalText is empty, want complete response")
	}
	if chunks <= 0 {
		t.Errorf("chunks received = %d, want > 0 (should have received at least one chunk)", chunks)
	}

	t.Logf("Received %d chunks, final response: %s", chunks, resp.FinalText)
}

// TestChatAgent_StreamingVsNonStreaming verifies that streaming and non-streaming
// modes produce equivalent results.
func TestChatAgent_StreamingVsNonStreaming(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx := context.Background()
	query := "What is 2+2? Answer with just the number."

	// Non-streaming execution:
	// ExecuteStream with nil callback executes in non-streaming mode.
	// This is a standard Go idiom (nil function = skip optional behavior).
	// Contract: When callback is nil, the method returns only after full completion.
	session1 := framework.CreateTestSession(t, "Non-streaming test")
	invCtx1, sessionID1 := newInvocationContext(ctx, session1)
	respNoStream, err := framework.Agent.ExecuteStream(invCtx1, sessionID1,
		query,
		nil, // No callback = non-streaming mode (returns complete response)
	)
	if err != nil {
		t.Fatalf("ExecuteStream() non-streaming unexpected error: %v", err)
	}
	if respNoStream == nil {
		t.Fatal("ExecuteStream() non-streaming response is nil, want non-nil when error is nil")
	}
	if respNoStream.FinalText == "" {
		t.Error("ExecuteStream() non-streaming response.FinalText is empty, want non-empty")
	}

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
	if err != nil {
		t.Fatalf("ExecuteStream() streaming unexpected error: %v", err)
	}
	if respStream == nil {
		t.Fatal("ExecuteStream() streaming response is nil, want non-nil when error is nil")
	}
	if respStream.FinalText == "" {
		t.Error("ExecuteStream() streaming response.FinalText is empty, want non-empty")
	}

	// Both should contain "4" (the answer)
	if !strings.Contains(respNoStream.FinalText, "4") {
		t.Errorf("ExecuteStream() non-streaming response = %q, want to contain %q", respNoStream.FinalText, "4")
	}
	if !strings.Contains(respStream.FinalText, "4") {
		t.Errorf("ExecuteStream() streaming response = %q, want to contain %q", respStream.FinalText, "4")
	}

	t.Logf("Non-streaming: %s", respNoStream.FinalText)
	t.Logf("Streaming: %s", respStream.FinalText)
}

// TestChatAgent_StreamingContextCancellation verifies that canceling the
// context stops streaming.
func TestChatAgent_StreamingContextCancellation(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	// Cancel BEFORE starting stream to guarantee cancellation
	// This is deterministic - no race between stream completion and cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, sessionID := newInvocationContext(context.Background(), framework.SessionID)

	resp, err := framework.Agent.ExecuteStream(ctx, sessionID,
		"Write a very long story",
		nil,
	)

	// Should fail with context canceled error
	if err == nil {
		t.Fatal("ExecuteStream() expected error, got nil (cancelled context should error)")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("ExecuteStream() error = %v, want context.Canceled", err)
	}
	if resp != nil {
		t.Errorf("ExecuteStream() response = %v, want nil (response should be nil when context is cancelled)", resp)
	}
	t.Logf("Context cancellation detected: %v", err)
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

	if err != nil {
		t.Fatalf("ExecuteStream() unexpected error: %v (should handle empty chunks gracefully)", err)
	}
	if resp.FinalText == "" {
		t.Error("ExecuteStream() response.FinalText is empty, want non-empty")
	}

	if emptyChunks > 0 {
		t.Logf("Received %d empty chunks out of %d total chunks", emptyChunks, totalChunks)
	} else {
		t.Logf("No empty chunks received (%d total chunks)", totalChunks)
	}
}
