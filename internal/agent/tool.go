package agent

import (
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// ToolInput is the input structure for agent-as-tool invocations.
// Note: SessionID is not exposed to the LLM and is managed automatically by the wrapper.
type ToolInput struct {
	Query string `json:"query" jsonschema:"description=Query to send to the agent"`
}

// DefineAgentTool registers an Agent as a Genkit Tool, enabling other agents
// to invoke it as a tool during execution.
//
// This function uses a closure pattern to capture the parent InvocationContext,
// allowing proper context propagation and history isolation through branch expansion.
//
// Design rationale:
//   - Package location prevents circular dependencies (agent → genkit, tools ⊥ agent)
//   - Follows Go's function-as-interface pattern (similar to http.HandlerFunc)
//
// Context propagation strategy:
//
//	The function captures parentCtx via closure rather than extracting from ai.ToolContext,
//	because ai.ToolContext does not guarantee InvocationContext presence. This approach
//	is simpler and more reliable.
//
// Branch expansion:
//
//	Each agent invocation extends the branch path (e.g., "main" → "main.research")
//	to isolate conversation histories while maintaining the same InvocationID for
//	call chain tracking.
//
// Example usage:
//
//	// Create a specialized research agent
//	researchAgent, err := NewResearchAgent(WithGenkit(g))
//	if err != nil {
//	    return err
//	}
//
//	// Register it as a tool during initialization
//	if err := DefineAgentTool(parentCtx, g, researchAgent); err != nil {
//	    return err
//	}
//
//	// Now the chat agent can invoke researchAgent during conversations
//	// The LLM will decide when to use it based on researchAgent.Description()
func DefineAgentTool(parentCtx InvocationContext, g *genkit.Genkit, a Agent) error {
	if g == nil {
		return fmt.Errorf("genkit instance is required")
	}
	if a == nil {
		return fmt.Errorf("agent is required")
	}
	if parentCtx == nil {
		return fmt.Errorf("parent invocation context is required")
	}

	// Wrap the agent as a Genkit Tool
	_ = genkit.DefineTool(
		g,
		a.Name(),
		a.Description(),
		func(toolCtx *ai.ToolContext, input ToolInput) (string, error) {
			// Extend the branch path for history isolation
			parentBranch := parentCtx.Branch()
			newBranch := parentBranch + "." + a.Name()

			// Create sub-context with:
			//   - Same InvocationID for call chain tracking
			//   - Extended Branch for history isolation
			//   - Same SessionID for session continuity
			//   - New AgentName for the sub-agent
			subCtx := NewInvocationContext(
				toolCtx.Context,
				parentCtx.InvocationID(),
				newBranch,
				parentCtx.SessionID(),
				a.Name(),
			)

			// Delegate execution to the agent
			resp, err := a.Execute(subCtx, input.Query)
			if err != nil {
				return "", fmt.Errorf("agent %s failed: %w", a.Name(), err)
			}

			return resp.FinalText, nil
		},
	)

	return nil
}

// DefineAgentToolWithContext is an advanced variant that allows dynamic context
// extraction for each invocation. This is useful when InvocationContext needs to
// be derived from ai.ToolContext at runtime.
//
// Warning: This approach requires the Chat Agent to inject InvocationContext into
// ai.ToolContext.Context before each invocation, adding complexity. For most use
// cases, DefineAgentTool is recommended.
//
// Example usage:
//
//	DefineAgentToolWithContext(g, researchAgent, func(toolCtx *ai.ToolContext) InvocationContext {
//	    return extractInvocationContext(toolCtx)
//	})
func DefineAgentToolWithContext(
	g *genkit.Genkit,
	a Agent,
	ctxExtractor func(*ai.ToolContext) InvocationContext,
) error {
	if g == nil {
		return fmt.Errorf("genkit instance is required")
	}
	if a == nil {
		return fmt.Errorf("agent is required")
	}
	if ctxExtractor == nil {
		return fmt.Errorf("context extractor is required")
	}

	_ = genkit.DefineTool(
		g,
		a.Name(),
		a.Description(),
		func(toolCtx *ai.ToolContext, input ToolInput) (string, error) {
			// Extract InvocationContext using the provided extractor
			parentCtx := ctxExtractor(toolCtx)
			if parentCtx == nil {
				return "", fmt.Errorf("failed to extract invocation context")
			}

			// Extend branch path
			parentBranch := parentCtx.Branch()
			newBranch := parentBranch + "." + a.Name()

			// Create sub-context
			subCtx := NewInvocationContext(
				toolCtx.Context,
				parentCtx.InvocationID(),
				newBranch,
				parentCtx.SessionID(),
				a.Name(),
			)

			// Execute agent
			resp, err := a.Execute(subCtx, input.Query)
			if err != nil {
				return "", fmt.Errorf("agent %s failed: %w", a.Name(), err)
			}

			return resp.FinalText, nil
		},
	)

	return nil
}
