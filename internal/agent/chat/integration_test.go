//go:build integration
// +build integration

package chat_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChatAgent_BasicExecution tests basic chat agent execution
func TestChatAgent_BasicExecution(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx := agent.NewInvocationContext(
		context.Background(),
		"test-inv-1",
		"main",
		agent.SessionID(framework.SessionID.String()),
		"chat",
	)

	t.Run("simple question", func(t *testing.T) {
		resp, err := framework.Agent.Execute(ctx, "Hello, how are you?")
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.FinalText, "Agent should provide a non-empty response")
	})

	t.Run("returns agent metadata", func(t *testing.T) {
		assert.Equal(t, "chat", framework.Agent.Name())
		assert.NotEmpty(t, framework.Agent.Description())
		assert.Nil(t, framework.Agent.SubAgents())
	})
}

// TestChatAgent_SessionPersistence tests conversation history persistence
func TestChatAgent_SessionPersistence(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx := agent.NewInvocationContext(
		context.Background(),
		"test-inv-2",
		"main",
		agent.SessionID(framework.SessionID.String()),
		"chat",
	)

	t.Run("first message creates history", func(t *testing.T) {
		resp, err := framework.Agent.Execute(ctx, "My name is Koopa")
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("second message uses history", func(t *testing.T) {
		// Create new invocation context with same session
		ctx2 := agent.NewInvocationContext(
			context.Background(),
			"test-inv-3",
			"main",
			agent.SessionID(framework.SessionID.String()),
			"chat",
		)

		resp, err := framework.Agent.Execute(ctx2, "What is my name?")
		require.NoError(t, err)
		assert.NotNil(t, resp)
		// Session history should allow LLM to remember the name from previous message
		assert.Contains(t, resp.FinalText, "Koopa", "LLM should remember 'Koopa' from session history")
	})
}

// TestChatAgent_ToolIntegration tests tool calling capability
func TestChatAgent_ToolIntegration(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx := agent.NewInvocationContext(
		context.Background(),
		"test-inv-4",
		"main",
		agent.SessionID(framework.SessionID.String()),
		"chat",
	)

	t.Run("can use file tools", func(t *testing.T) {
		// Ask agent to list files - LLM decides whether to call tools
		resp, err := framework.Agent.Execute(ctx, "List the files in /tmp directory")
		require.NoError(t, err)
		assert.NotNil(t, resp)
		// Agent should respond (with or without tool calls)
		assert.NotEmpty(t, resp.FinalText, "Agent should provide a response")
	})
}

// TestChatAgent_ErrorHandling tests error scenarios
func TestChatAgent_ErrorHandling(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	t.Run("handles empty input gracefully", func(t *testing.T) {
		ctx := agent.NewInvocationContext(
			context.Background(),
			"test-inv-5",
			"main",
			agent.SessionID(framework.SessionID.String()),
			"chat",
		)

		resp, err := framework.Agent.Execute(ctx, "")
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

	t.Run("requires config", func(t *testing.T) {
		_, err := chat.New(chat.Deps{
			Genkit:         framework.Genkit,
			Retriever:      framework.Retriever,
			SessionStore:   framework.SessionStore,
			KnowledgeStore: framework.KnowledgeStore,
			Logger:         slog.Default(),
			Toolsets:       []tools.Toolset{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Config is required")
	})

	t.Run("requires genkit", func(t *testing.T) {
		_, err := chat.New(chat.Deps{
			Config:         framework.Config,
			Retriever:      framework.Retriever,
			SessionStore:   framework.SessionStore,
			KnowledgeStore: framework.KnowledgeStore,
			Logger:         slog.Default(),
			Toolsets:       []tools.Toolset{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Genkit is required")
	})

	t.Run("requires retriever", func(t *testing.T) {
		_, err := chat.New(chat.Deps{
			Config:         framework.Config,
			Genkit:         framework.Genkit,
			SessionStore:   framework.SessionStore,
			KnowledgeStore: framework.KnowledgeStore,
			Logger:         slog.Default(),
			Toolsets:       []tools.Toolset{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Retriever is required")
	})

	t.Run("requires session store", func(t *testing.T) {
		_, err := chat.New(chat.Deps{
			Config:         framework.Config,
			Genkit:         framework.Genkit,
			Retriever:      framework.Retriever,
			KnowledgeStore: framework.KnowledgeStore,
			Logger:         slog.Default(),
			Toolsets:       []tools.Toolset{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SessionStore is required")
	})

	t.Run("requires knowledge store", func(t *testing.T) {
		_, err := chat.New(chat.Deps{
			Config:       framework.Config,
			Genkit:       framework.Genkit,
			Retriever:    framework.Retriever,
			SessionStore: framework.SessionStore,
			Logger:       slog.Default(),
			Toolsets:     []tools.Toolset{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "KnowledgeStore is required")
	})

	t.Run("requires logger", func(t *testing.T) {
		_, err := chat.New(chat.Deps{
			Config:         framework.Config,
			Genkit:         framework.Genkit,
			Retriever:      framework.Retriever,
			SessionStore:   framework.SessionStore,
			KnowledgeStore: framework.KnowledgeStore,
			Toolsets:       []tools.Toolset{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Logger is required")
	})

	t.Run("requires at least one toolset", func(t *testing.T) {
		_, err := chat.New(chat.Deps{
			Config:         framework.Config,
			Genkit:         framework.Genkit,
			Retriever:      framework.Retriever,
			SessionStore:   framework.SessionStore,
			KnowledgeStore: framework.KnowledgeStore,
			Logger:         slog.Default(),
			Toolsets:       []tools.Toolset{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Toolsets is required")
	})
}
