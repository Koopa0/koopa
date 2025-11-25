package agent

import (
	"github.com/firebase/genkit/go/ai"
)

// Response represents the complete result of an agent execution.
type Response struct {
	FinalText    string            // Model's final text output
	History      []*ai.Message     // Complete conversation history including all tool calls
	ToolRequests []*ai.ToolRequest // Tool requests made during execution
}

// Agent defines the core interface for all Agents
type Agent interface {
	// Name returns the unique identifier for the Agent
	Name() string

	// Description returns the functional description of the Agent
	// Used by LLM to understand and select appropriate Agent in multi-agent scenarios
	Description() string

	// Execute runs the Agent's core logic
	// Corresponds to ADK's Run() method but uses Genkit's synchronous mode
	Execute(ctx InvocationContext, input string) (*Response, error)

	// SubAgents returns child Agents that this Agent can delegate to
	// Reserved for multi-agent hierarchical structure
	SubAgents() []Agent
}
