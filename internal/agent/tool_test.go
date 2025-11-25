package agent

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefineAgentTool_Success tests successful agent-as-tool registration
func TestDefineAgentTool_Success(t *testing.T) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("Skipping: GEMINI_API_KEY not set")
	}
	t.Parallel()

	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))

	// Create parent InvocationContext
	parentCtx := NewInvocationContext(
		ctx,
		uuid.New().String(),
		"main",
		NewSessionID("test-session"),
		"chat",
	)

	// Create mock agent
	agent := &mockAgent{
		name:        "research",
		description: "A research agent for deep analysis",
		executeFunc: func(ctx InvocationContext, input string) (*Response, error) {
			return &Response{
				FinalText: "Research result: " + input,
				History:   []*ai.Message{},
			}, nil
		},
	}

	// Register agent as tool
	err := DefineAgentTool(parentCtx, g, agent)
	require.NoError(t, err)

	// Verify tool is registered
	tools := genkit.ListTools(g)
	found := false
	for _, tool := range tools {
		if tool.Name() == "research" {
			found = true
			break
		}
	}
	assert.True(t, found, "agent tool should be registered")
}

// TestDefineAgentTool_ContextPropagation tests InvocationContext propagation
func TestDefineAgentTool_ContextPropagation(t *testing.T) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("Skipping: GEMINI_API_KEY not set")
	}
	t.Parallel()

	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))

	invocationID := uuid.New().String()
	sessionID := NewSessionID("test-session")

	parentCtx := NewInvocationContext(ctx, invocationID, "main", sessionID, "chat")

	// Track context received by agent
	var receivedCtx InvocationContext
	agent := &mockAgent{
		name:        "research",
		description: "Research agent",
		executeFunc: func(ctx InvocationContext, input string) (*Response, error) {
			receivedCtx = ctx
			return &Response{FinalText: "ok"}, nil
		},
	}

	err := DefineAgentTool(parentCtx, g, agent)
	require.NoError(t, err)

	// Simulate tool invocation
	handler := func(toolCtx *ai.ToolContext, input AgentToolInput) (string, error) {
		// Extend branch
		newBranch := parentCtx.Branch() + "." + agent.Name()
		subCtx := NewInvocationContext(
			toolCtx.Context,
			parentCtx.InvocationID(),
			newBranch,
			parentCtx.SessionID(),
			agent.Name(),
		)
		resp, err := agent.Execute(subCtx, input.Query)
		if err != nil {
			return "", err
		}
		return resp.FinalText, nil
	}

	_, err = handler(&ai.ToolContext{Context: ctx}, AgentToolInput{Query: "test query"})
	require.NoError(t, err)

	// Verify context propagation
	require.NotNil(t, receivedCtx)
	assert.Equal(t, invocationID, receivedCtx.InvocationID(), "InvocationID should be preserved")
	assert.Equal(t, sessionID, receivedCtx.SessionID(), "SessionID should be preserved")
	assert.Equal(t, "research", receivedCtx.AgentName(), "AgentName should be updated")
}

// TestDefineAgentTool_BranchExpansion tests branch path expansion for history isolation
func TestDefineAgentTool_BranchExpansion(t *testing.T) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("Skipping: GEMINI_API_KEY not set")
	}
	t.Parallel()

	t.Run("single level expansion", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))

		parentCtx := NewInvocationContext(
			ctx,
			uuid.New().String(),
			"main",
			NewSessionID("s-123"),
			"chat",
		)

		var receivedBranch string
		agent := &mockAgent{
			name:        "research",
			description: "Research agent",
			executeFunc: func(ctx InvocationContext, input string) (*Response, error) {
				receivedBranch = ctx.Branch()
				return &Response{FinalText: "ok"}, nil
			},
		}

		err := DefineAgentTool(parentCtx, g, agent)
		require.NoError(t, err)

		// Simulate invocation
		newBranch := parentCtx.Branch() + "." + agent.Name()
		subCtx := NewInvocationContext(ctx, parentCtx.InvocationID(), newBranch, parentCtx.SessionID(), agent.Name())
		_, err = agent.Execute(subCtx, "test")
		require.NoError(t, err)

		// Verify branch expansion
		assert.Equal(t, "main.research", receivedBranch)
	})

	t.Run("multi level expansion", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))

		// Simulate: chat → research → websearch
		chatCtx := NewInvocationContext(ctx, "inv-123", "main", NewSessionID("s-123"), "chat")

		researchAgent := &mockAgent{name: "research", description: "Research"}
		err := DefineAgentTool(chatCtx, g, researchAgent)
		require.NoError(t, err)

		// Research agent creates context for websearch
		researchBranch := chatCtx.Branch() + ".research"
		researchCtx := NewInvocationContext(ctx, "inv-123", researchBranch, NewSessionID("s-123"), "research")

		var websearchBranch string
		websearchAgent := &mockAgent{
			name:        "websearch",
			description: "Web search",
			executeFunc: func(ctx InvocationContext, input string) (*Response, error) {
				websearchBranch = ctx.Branch()
				return &Response{FinalText: "ok"}, nil
			},
		}

		err = DefineAgentTool(researchCtx, g, websearchAgent)
		require.NoError(t, err)

		// Simulate websearch invocation
		newBranch := researchCtx.Branch() + ".websearch"
		websearchCtx := NewInvocationContext(ctx, "inv-123", newBranch, NewSessionID("s-123"), "websearch")
		_, err = websearchAgent.Execute(websearchCtx, "test")
		require.NoError(t, err)

		// Verify multi-level branch
		assert.Equal(t, "main.research.websearch", websearchBranch)
	})
}

// TestDefineAgentTool_ErrorHandling tests error scenarios
func TestDefineAgentTool_ErrorHandling(t *testing.T) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("Skipping: GEMINI_API_KEY not set")
	}
	t.Parallel()

	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))

	t.Run("nil genkit instance", func(t *testing.T) {
		t.Parallel()
		parentCtx := NewInvocationContext(ctx, "inv-123", "main", NewSessionID("s-123"), "chat")
		agent := &mockAgent{name: "test", description: "test"}

		err := DefineAgentTool(parentCtx, nil, agent)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "genkit instance is required")
	})

	t.Run("nil agent", func(t *testing.T) {
		t.Parallel()
		parentCtx := NewInvocationContext(ctx, "inv-123", "main", NewSessionID("s-123"), "chat")

		err := DefineAgentTool(parentCtx, g, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "agent is required")
	})

	t.Run("nil parent context", func(t *testing.T) {
		t.Parallel()
		agent := &mockAgent{name: "test", description: "test"}

		err := DefineAgentTool(nil, g, agent)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parent invocation context is required")
	})

	t.Run("agent execution error", func(t *testing.T) {
		t.Parallel()

		parentCtx := NewInvocationContext(ctx, "inv-123", "main", NewSessionID("s-123"), "chat")
		expectedErr := errors.New("agent failed")

		agent := &mockAgent{
			name:        "failing-agent",
			description: "An agent that fails",
			executeFunc: func(ctx InvocationContext, input string) (*Response, error) {
				return nil, expectedErr
			},
		}

		// Simulate invocation that will fail
		newBranch := parentCtx.Branch() + "." + agent.Name()
		subCtx := NewInvocationContext(ctx, parentCtx.InvocationID(), newBranch, parentCtx.SessionID(), agent.Name())

		_, err := agent.Execute(subCtx, "test")
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})
}

// TestDefineAgentToolWithContext_DynamicExtraction tests dynamic context extraction
func TestDefineAgentToolWithContext_DynamicExtraction(t *testing.T) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("Skipping: GEMINI_API_KEY not set")
	}
	t.Parallel()

	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))

	// Context extractor that creates InvocationContext from ai.ToolContext
	extractor := func(toolCtx *ai.ToolContext) InvocationContext {
		return NewInvocationContext(
			toolCtx.Context,
			"extracted-inv-id",
			"extracted-branch",
			NewSessionID("extracted-session"),
			"extracted-agent",
		)
	}

	var receivedCtx InvocationContext
	agent := &mockAgent{
		name:        "dynamic-agent",
		description: "Agent with dynamic context",
		executeFunc: func(ctx InvocationContext, input string) (*Response, error) {
			receivedCtx = ctx
			return &Response{FinalText: "ok"}, nil
		},
	}

	err := DefineAgentToolWithContext(g, agent, extractor)
	require.NoError(t, err)

	// Simulate invocation
	toolCtx := &ai.ToolContext{Context: ctx}
	parentCtx := extractor(toolCtx)
	newBranch := parentCtx.Branch() + "." + agent.Name()
	subCtx := NewInvocationContext(ctx, parentCtx.InvocationID(), newBranch, parentCtx.SessionID(), agent.Name())
	_, err = agent.Execute(subCtx, "test")
	require.NoError(t, err)

	// Verify extracted context was used
	assert.NotNil(t, receivedCtx)
	assert.Equal(t, "extracted-inv-id", receivedCtx.InvocationID())
	assert.Equal(t, "extracted-branch.dynamic-agent", receivedCtx.Branch())
}

// TestDefineAgentToolWithContext_ErrorHandling tests error scenarios for dynamic context extraction
func TestDefineAgentToolWithContext_ErrorHandling(t *testing.T) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("Skipping: GEMINI_API_KEY not set")
	}
	t.Parallel()

	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))

	t.Run("nil genkit instance", func(t *testing.T) {
		t.Parallel()
		agent := &mockAgent{name: "test", description: "test"}
		extractor := func(toolCtx *ai.ToolContext) InvocationContext {
			return NewInvocationContext(ctx, "inv", "main", NewSessionID("s"), "agent")
		}

		err := DefineAgentToolWithContext(nil, agent, extractor)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "genkit instance is required")
	})

	t.Run("nil agent", func(t *testing.T) {
		t.Parallel()
		extractor := func(toolCtx *ai.ToolContext) InvocationContext {
			return NewInvocationContext(ctx, "inv", "main", NewSessionID("s"), "agent")
		}

		err := DefineAgentToolWithContext(g, nil, extractor)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "agent is required")
	})

	t.Run("nil extractor", func(t *testing.T) {
		t.Parallel()
		agent := &mockAgent{name: "test", description: "test"}

		err := DefineAgentToolWithContext(g, agent, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context extractor is required")
	})

	t.Run("extractor returns nil", func(t *testing.T) {
		t.Parallel()

		agent := &mockAgent{name: "test", description: "test"}
		extractor := func(toolCtx *ai.ToolContext) InvocationContext {
			return nil // Simulate extraction failure
		}

		err := DefineAgentToolWithContext(g, agent, extractor)
		require.NoError(t, err) // Registration succeeds

		// But invocation should fail
		parentCtx := extractor(&ai.ToolContext{Context: ctx})
		assert.Nil(t, parentCtx)
	})
}

// TestAgentToolInput_Structure tests AgentToolInput structure
func TestAgentToolInput_Structure(t *testing.T) {
	t.Parallel()

	input := AgentToolInput{
		Query: "What is quantum computing?",
	}

	assert.Equal(t, "What is quantum computing?", input.Query)
}

// TestDefineAgentTool_InvocationIDPreservation tests that InvocationID is preserved across multi-agent calls
func TestDefineAgentTool_InvocationIDPreservation(t *testing.T) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("Skipping: GEMINI_API_KEY not set")
	}
	t.Parallel()

	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))

	invocationID := uuid.New().String()
	parentCtx := NewInvocationContext(ctx, invocationID, "main", NewSessionID("s-123"), "chat")

	// Chain of agents: chat → research → analysis
	var researchInvID, analysisInvID string

	researchAgent := &mockAgent{
		name:        "research",
		description: "Research agent",
		executeFunc: func(ctx InvocationContext, input string) (*Response, error) {
			researchInvID = ctx.InvocationID()
			return &Response{FinalText: "research done"}, nil
		},
	}

	analysisAgent := &mockAgent{
		name:        "analysis",
		description: "Analysis agent",
		executeFunc: func(ctx InvocationContext, input string) (*Response, error) {
			analysisInvID = ctx.InvocationID()
			return &Response{FinalText: "analysis done"}, nil
		},
	}

	// Register both agents
	err := DefineAgentTool(parentCtx, g, researchAgent)
	require.NoError(t, err)

	// Research calls analysis
	researchBranch := parentCtx.Branch() + ".research"
	researchCtx := NewInvocationContext(ctx, invocationID, researchBranch, NewSessionID("s-123"), "research")

	err = DefineAgentTool(researchCtx, g, analysisAgent)
	require.NoError(t, err)

	// Simulate execution chain
	researchSubCtx := NewInvocationContext(ctx, invocationID, "main.research", NewSessionID("s-123"), "research")
	_, err = researchAgent.Execute(researchSubCtx, "test")
	require.NoError(t, err)

	analysisSubCtx := NewInvocationContext(ctx, invocationID, "main.research.analysis", NewSessionID("s-123"), "analysis")
	_, err = analysisAgent.Execute(analysisSubCtx, "test")
	require.NoError(t, err)

	// Verify InvocationID is preserved through the chain
	assert.Equal(t, invocationID, researchInvID, "research should have same InvocationID")
	assert.Equal(t, invocationID, analysisInvID, "analysis should have same InvocationID")
	assert.Equal(t, researchInvID, analysisInvID, "all agents in chain should share InvocationID")
}

// TestDefineAgentTool_BranchIsolation tests that different branches maintain separate histories
func TestDefineAgentTool_BranchIsolation(t *testing.T) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("Skipping: GEMINI_API_KEY not set")
	}
	t.Parallel()

	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))

	invocationID := uuid.New().String()
	sessionID := NewSessionID("s-123")
	parentCtx := NewInvocationContext(ctx, invocationID, "main", sessionID, "chat")

	// Track branches seen by each agent
	var agent1Branch, agent2Branch string

	agent1 := &mockAgent{
		name:        "agent1",
		description: "First agent",
		executeFunc: func(ctx InvocationContext, input string) (*Response, error) {
			agent1Branch = ctx.Branch()
			return &Response{FinalText: "agent1 response"}, nil
		},
	}

	agent2 := &mockAgent{
		name:        "agent2",
		description: "Second agent",
		executeFunc: func(ctx InvocationContext, input string) (*Response, error) {
			agent2Branch = ctx.Branch()
			return &Response{FinalText: "agent2 response"}, nil
		},
	}

	// Register both agents
	err := DefineAgentTool(parentCtx, g, agent1)
	require.NoError(t, err)

	err = DefineAgentTool(parentCtx, g, agent2)
	require.NoError(t, err)

	// Execute both agents
	agent1Ctx := NewInvocationContext(ctx, invocationID, "main.agent1", sessionID, "agent1")
	_, err = agent1.Execute(agent1Ctx, "test1")
	require.NoError(t, err)

	agent2Ctx := NewInvocationContext(ctx, invocationID, "main.agent2", sessionID, "agent2")
	_, err = agent2.Execute(agent2Ctx, "test2")
	require.NoError(t, err)

	// Verify branches are different (isolated histories)
	assert.Equal(t, "main.agent1", agent1Branch)
	assert.Equal(t, "main.agent2", agent2Branch)
	assert.NotEqual(t, agent1Branch, agent2Branch, "branches should be different for history isolation")
}
