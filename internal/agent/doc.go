// Package agent provides the core agent abstraction and execution framework.
//
// # Overview
//
// This package defines the Agent interface and provides infrastructure for building
// conversational AI agents with tool-calling capabilities. It supports both single-agent
// and multi-agent architectures through the agent-as-tool pattern.
//
// # Core Concepts
//
// Agent: The fundamental abstraction representing an AI agent that can process
// queries and invoke tools.
//
//	type Agent interface {
//	    Name() string
//	    Description() string
//	    Execute(ctx InvocationContext, query string) (*Response, error)
//	}
//
// InvocationContext: Encapsulates execution context for agent invocations,
// including session tracking, branching for history isolation, and invocation
// chain tracking.
//
//	type InvocationContext interface {
//	    InvocationID() string  // Unique ID for this execution
//	    Branch() string        // History branch path (e.g., "main.research")
//	    SessionID() SessionID  // Session identifier
//	    AgentName() string     // Current agent name
//	}
//
// # Agent-as-Tool Pattern
//
// The DefineAgentTool function enables multi-agent collaboration by registering
// an agent as a Genkit tool that other agents can invoke:
//
//	// Create a specialized research agent
//	researchAgent, err := NewResearchAgent(WithGenkit(g))
//	if err != nil {
//	    return err
//	}
//
//	// Register it as a tool accessible to other agents
//	if err := DefineAgentTool(parentCtx, g, researchAgent); err != nil {
//	    return err
//	}
//
// When one agent invokes another as a tool:
//   - The InvocationID remains the same (tracks the entire call chain)
//   - The Branch extends (e.g., "main" → "main.research")
//   - The SessionID stays the same (maintains session continuity)
//   - The AgentName updates to reflect the current agent
//
// This design allows proper history isolation while maintaining context across
// agent boundaries.
//
// # History and Session Management
//
// Branch-based history isolation ensures that when agent A invokes agent B,
// their conversation histories are stored separately:
//
//	Session: user-session-123
//	  Branch: main              → Agent A's history
//	  Branch: main.research     → Agent B's history (invoked by A)
//	  Branch: main.analysis     → Agent C's history (invoked by A)
//
// This prevents context pollution while allowing each agent to maintain
// its own coherent conversation thread.
//
// # Types and Identifiers
//
// SessionID: Identifies a conversation session across agent invocations
//
//	type SessionID = uuid.UUID
//
// InvocationID: Tracks a single execution chain, even across multiple agents
//
//	type InvocationID = string
//
// # Implementation Example
//
// The chat subpackage provides a complete implementation:
//
//	import "github.com/koopa0/koopa-cli/internal/agent/chat"
//
//	chatAgent, err := chat.New(
//	    chat.WithGenkit(g),
//	    chat.WithConfig(cfg),
//	    chat.WithToolsets(fileToolset, systemToolset),
//	    chat.WithSessionStore(sessionStore),
//	)
//
// # Extension Points
//
// To implement a custom agent:
//
//  1. Implement the Agent interface
//  2. Use InvocationContext for proper context handling
//  3. Optionally register as a tool using DefineAgentTool
//  4. Handle history persistence using the provided SessionStore
//
// See the chat subpackage for a complete reference implementation.
package agent
