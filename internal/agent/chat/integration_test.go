//go:build integration
// +build integration

package chat_test

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/koopa0/koopa/internal/agent/chat"
)

// TestChatAgent_BasicExecution tests basic chat agent execution
func TestChatAgent_BasicExecution(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx, sessionID := newInvocationContext(context.Background(), framework.SessionID)

	t.Run("simple question", func(t *testing.T) {
		resp, err := framework.Agent.Execute(ctx, sessionID, "Hello, how are you?")
		require.NoError(t, err)
		require.NotNil(t, resp, "Response should not be nil when error is nil")
		assert.NotEmpty(t, resp.FinalText, "Agent should provide a non-empty response")
	})
}

// TestChatAgent_SessionPersistence tests conversation history persistence
func TestChatAgent_SessionPersistence(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx, sessionID := newInvocationContext(context.Background(), framework.SessionID)

	t.Run("first message creates history", func(t *testing.T) {
		resp, err := framework.Agent.Execute(ctx, sessionID, "My name is Koopa")
		require.NoError(t, err)
		require.NotNil(t, resp, "Response should not be nil when error is nil")
	})

	t.Run("second message uses history", func(t *testing.T) {
		// Use same session for history continuity
		resp, err := framework.Agent.Execute(ctx, sessionID, "What is my name?")
		require.NoError(t, err)
		require.NotNil(t, resp, "Response should not be nil when error is nil")
		// Session history should allow LLM to remember the name from previous message
		assert.Contains(t, resp.FinalText, "Koopa", "LLM should remember 'Koopa' from session history")
	})
}

// TestChatAgent_ToolIntegration tests tool calling capability
func TestChatAgent_ToolIntegration(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx, sessionID := newInvocationContext(context.Background(), framework.SessionID)

	t.Run("can use file tools", func(t *testing.T) {
		// Ask agent to list files - LLM decides whether to call tools
		resp, err := framework.Agent.Execute(ctx, sessionID, "List the files in /tmp directory")
		require.NoError(t, err)
		require.NotNil(t, resp, "Response should not be nil when error is nil")
		// Agent should respond (with or without tool calls)
		assert.NotEmpty(t, resp.FinalText, "Agent should provide a response")
	})
}

// TestChatAgent_ErrorHandling tests error scenarios
func TestChatAgent_ErrorHandling(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	t.Run("handles empty input gracefully", func(t *testing.T) {
		ctx, sessionID := newInvocationContext(context.Background(), framework.SessionID)

		resp, err := framework.Agent.Execute(ctx, sessionID, "")
		// Should handle empty input without crashing
		// Either returns error or empty response
		if err == nil {
			assert.NotNil(t, resp)
		}
	})
}

// TestChatAgent_NewChatValidation tests constructor validation
func TestChatAgent_NewChatValidation(t *testing.T) {
	// Setup test framework once for all validation tests
	framework, cleanup := SetupTest(t)
	defer cleanup()

	t.Run("requires genkit", func(t *testing.T) {
		_, err := chat.New(chat.Config{
			Retriever:    framework.Retriever,
			SessionStore: framework.SessionStore,
			Logger:       slog.Default(),
			Tools:        []ai.Tool{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "genkit instance is required")
	})

	t.Run("requires retriever", func(t *testing.T) {
		_, err := chat.New(chat.Config{
			Genkit:       framework.Genkit,
			SessionStore: framework.SessionStore,
			Logger:       slog.Default(),
			Tools:        []ai.Tool{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "retriever is required")
	})

	t.Run("requires session store", func(t *testing.T) {
		_, err := chat.New(chat.Config{
			Genkit:    framework.Genkit,
			Retriever: framework.Retriever,
			Logger:    slog.Default(),
			Tools:     []ai.Tool{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "session store is required")
	})

	t.Run("requires logger", func(t *testing.T) {
		_, err := chat.New(chat.Config{
			Genkit:       framework.Genkit,
			Retriever:    framework.Retriever,
			SessionStore: framework.SessionStore,
			Tools:        []ai.Tool{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("requires at least one tool", func(t *testing.T) {
		_, err := chat.New(chat.Config{
			Genkit:       framework.Genkit,
			Retriever:    framework.Retriever,
			SessionStore: framework.SessionStore,
			Logger:       slog.Default(),
			Tools:        []ai.Tool{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one tool is required")
	})
}

// TestChatAgent_ConcurrentExecution tests concurrent chat agent execution.
// Uses mutex-protected error collection instead of assert/require in goroutines
// to avoid test reliability issues with t.FailNow() from goroutines.
func TestChatAgent_ConcurrentExecution(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	numConcurrentQueries := 5
	var wg sync.WaitGroup
	wg.Add(numConcurrentQueries)

	ctx, sessionID := newInvocationContext(context.Background(), framework.SessionID)

	// Collect results safely
	type result struct {
		queryID int
		resp    *chat.Response
		err     error
	}
	results := make([]result, numConcurrentQueries)
	var mu sync.Mutex

	for i := 0; i < numConcurrentQueries; i++ {
		go func(queryID int) {
			defer wg.Done()
			resp, err := framework.Agent.Execute(ctx, sessionID, fmt.Sprintf("What is the capital of France? Query ID: %d", queryID))
			mu.Lock()
			results[queryID] = result{queryID: queryID, resp: resp, err: err}
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Assert after all goroutines complete
	for _, r := range results {
		require.NoError(t, r.err, "Concurrent query %d should not return an error", r.queryID)
		assert.NotNil(t, r.resp, "Concurrent query %d response should not be nil", r.queryID)
		if r.resp != nil {
			assert.NotEmpty(t, r.resp.FinalText, "Concurrent query %d should provide a non-empty response", r.queryID)
			assert.Contains(t, r.resp.FinalText, "Paris", "Concurrent query %d should identify Paris as the capital", r.queryID)
		}
	}
}
