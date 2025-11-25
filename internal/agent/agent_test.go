package agent

import (
	"context"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResponse_Structure tests Response struct
func TestResponse_Structure(t *testing.T) {
	t.Parallel()

	t.Run("basic response creation", func(t *testing.T) {
		t.Parallel()
		resp := &Response{
			FinalText: "Hello, world!",
			History: []*ai.Message{
				ai.NewUserMessage(ai.NewTextPart("Hi")),
			},
			ToolRequests: []*ai.ToolRequest{},
		}

		assert.Equal(t, "Hello, world!", resp.FinalText)
		assert.Len(t, resp.History, 1)
		assert.Empty(t, resp.ToolRequests)
	})

	t.Run("response with tool requests", func(t *testing.T) {
		t.Parallel()
		toolReq := &ai.ToolRequest{
			Name:  "readFile",
			Input: map[string]any{"path": "/tmp/test.txt"},
		}

		resp := &Response{
			FinalText:    "Reading file...",
			History:      []*ai.Message{},
			ToolRequests: []*ai.ToolRequest{toolReq},
		}

		assert.Len(t, resp.ToolRequests, 1)
		assert.Equal(t, "readFile", resp.ToolRequests[0].Name)
	})
}

// mockAgent is a simple Agent implementation for testing
type mockAgent struct {
	name        string
	description string
	executeFunc func(ctx InvocationContext, input string) (*Response, error)
	subAgents   []Agent
}

func (m *mockAgent) Name() string        { return m.name }
func (m *mockAgent) Description() string { return m.description }
func (m *mockAgent) SubAgents() []Agent  { return m.subAgents }
func (m *mockAgent) Execute(ctx InvocationContext, input string) (*Response, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, input)
	}
	return &Response{FinalText: "mock response"}, nil
}

// TestAgent_Interface tests Agent interface implementation
func TestAgent_Interface(t *testing.T) {
	t.Parallel()

	t.Run("mock agent implements interface", func(t *testing.T) {
		t.Parallel()
		var _ Agent = (*mockAgent)(nil) // compile-time check

		agent := &mockAgent{
			name:        "test-agent",
			description: "A test agent",
		}

		assert.Equal(t, "test-agent", agent.Name())
		assert.Equal(t, "A test agent", agent.Description())
		assert.Empty(t, agent.SubAgents())
	})

	t.Run("agent with sub-agents", func(t *testing.T) {
		t.Parallel()
		subAgent1 := &mockAgent{name: "sub1", description: "Sub agent 1"}
		subAgent2 := &mockAgent{name: "sub2", description: "Sub agent 2"}

		parentAgent := &mockAgent{
			name:        "parent",
			description: "Parent agent",
			subAgents:   []Agent{subAgent1, subAgent2},
		}

		require.Len(t, parentAgent.SubAgents(), 2)
		assert.Equal(t, "sub1", parentAgent.SubAgents()[0].Name())
		assert.Equal(t, "sub2", parentAgent.SubAgents()[1].Name())
	})

	t.Run("agent execution", func(t *testing.T) {
		t.Parallel()
		executed := false
		agent := &mockAgent{
			name: "test",
			executeFunc: func(ctx InvocationContext, input string) (*Response, error) {
				executed = true
				return &Response{FinalText: "executed: " + input}, nil
			},
		}

		ctx := NewInvocationContext(
			context.Background(),
			"inv-123",
			"main",
			NewSessionID("s-123"),
			"test",
		)

		resp, err := agent.Execute(ctx, "test input")
		require.NoError(t, err)
		assert.True(t, executed)
		assert.Equal(t, "executed: test input", resp.FinalText)
	})
}
