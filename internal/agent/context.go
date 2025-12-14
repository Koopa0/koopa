// Package agent provides the Agent interface and implementations.
//
// # DESIGN DECISION: Context Embedding
//
// This package uses context embedding in InvocationContext, which violates
// the standard Go guideline (https://go.dev/blog/context-and-structs).
//
// ## Rationale for Exception
//
// 1. Agent Framework Requirements:
//   - Multi-agent delegation chains (tracked via InvocationID)
//   - Session-scoped state (SessionID persists across calls)
//   - Branch isolation (separate histories per agent path)
//   - Metadata propagation (AgentName for logging/debugging)
//
// 2. These requirements don't map to context.Context's design:
//
//   - context.Context is for request-scoped cancellation/deadlines
//
//   - Agent metadata is conversation-scoped (longer lifetime)
//
//   - Type-unsafe context.WithValue() loses compile-time safety
//
//     3. API Clarity:
//     Execute(ctx InvocationContext, input string)  // Clear
//     vs
//     Execute(ctx context.Context, meta Metadata, input string)  // Confusing
//
//     4. Precedent:
//     The Go team acknowledges exceptions for specialized frameworks
//     (backwards compatibility is one; agent orchestration is another)
//
// ## Mitigation
//
//   - Unwrap() method extracts context.Context for stdlib integration
//   - Clear documentation of lifetime semantics
//   - Explicit typing prevents misuse
//
// This is a deliberate, documented trade-off optimizing for agent framework
// ergonomics over strict adherence to general-purpose Go guidelines.
package agent

import (
	"context"
	"errors"
)

// InvocationContext provides complete context for Agent execution
// Fully aligned with ADK-Go design principles, simplified for personal AI
//
// Design principles:
// - InvocationID: Tracks entire multi-agent call chain (all sub-Agents share same ID)
// - Branch: Isolates Agent history (e.g., chat.research.websearch)
// - SessionID: User session management
// - AgentName: Current Agent name for debugging and logging
type InvocationContext interface {
	context.Context // Embeds standard Context for compatibility

	// InvocationID is the unique identifier for the entire call chain
	// Example: chat → research → websearch share the same InvocationID
	// Used for: DevUI tracing, logging, metrics
	InvocationID() string

	// Branch format: "agent1.agent2.agent3"
	// Example: "chat.research.websearch"
	// Used by SessionStore to isolate history for different Agents
	Branch() string

	// SessionID is the unique identifier for user session
	SessionID() SessionID

	// AgentName is the name of the current Agent
	AgentName() string

	// Unwrap returns the underlying context.Context for stdlib integration.
	// Use this when calling standard library functions that require context.Context:
	//   - http.NewRequestWithContext(invCtx.Unwrap(), ...)
	//   - db.QueryContext(invCtx.Unwrap(), ...)
	//   - cancel, timeout propagation
	// This provides an "escape hatch" from the embedded context pattern.
	Unwrap() context.Context
}

// ReadonlyContext provides read-only Context for Tools
// Design principle: Tools should only read Context, not modify it
type ReadonlyContext interface {
	InvocationID() string
	Branch() string
	SessionID() SessionID
	AgentName() string
}

// NOTE: contextKey and sessionIDKey were removed as they were unused.
// If context-based session ID storage is needed in the future, redefine:
//   type contextKey string
//   const sessionIDKey contextKey = "session_id"

// SessionID is a dedicated type for session identifiers
type SessionID string

// ErrEmptySessionID is returned when session ID is empty
var ErrEmptySessionID = errors.New("session ID cannot be empty")

// ErrSessionIDTooLong is returned when session ID exceeds max length
var ErrSessionIDTooLong = errors.New("session ID too long (max 255)")

// NewSessionID creates a new SessionID with validation
// Returns error if the session ID is empty or exceeds max length (255 characters)
func NewSessionID(id string) (SessionID, error) {
	if id == "" {
		return "", ErrEmptySessionID
	}
	if len(id) > 255 {
		return "", ErrSessionIDTooLong
	}
	return SessionID(id), nil
}

// String returns the string representation of SessionID
func (s SessionID) String() string {
	return string(s)
}

// IsEmpty checks if SessionID is empty
func (s SessionID) IsEmpty() bool {
	return s == ""
}

// invocationContext is the private implementation of InvocationContext
type invocationContext struct {
	context.Context
	invocationID string
	branch       string
	sessionID    SessionID
	agentName    string
}

// NewInvocationContext creates a new InvocationContext
//
// Parameters:
// - parent: Parent Context for cancellation, timeout, values
// - invocationID: Unique ID for the call chain (shared across multi-agent)
// - branch: Agent hierarchy (e.g., "chat.research")
// - sessionID: Session ID
// - agentName: Current Agent name
func NewInvocationContext(
	parent context.Context,
	invocationID string,
	branch string,
	sessionID SessionID,
	agentName string,
) InvocationContext {
	return &invocationContext{
		Context:      parent,
		invocationID: invocationID,
		branch:       branch,
		sessionID:    sessionID,
		agentName:    agentName,
	}
}

// InvocationID returns the unique identifier for this invocation.
func (ic *invocationContext) InvocationID() string { return ic.invocationID }

// Branch returns the conversation branch name.
func (ic *invocationContext) Branch() string { return ic.branch }

// SessionID returns the session identifier.
func (ic *invocationContext) SessionID() SessionID { return ic.sessionID }

// AgentName returns the name of the executing agent.
func (ic *invocationContext) AgentName() string { return ic.agentName }

// Unwrap returns the underlying context.Context for stdlib integration.
func (ic *invocationContext) Unwrap() context.Context { return ic.Context }

// AsReadonly returns a read-only version
// invocationContext already implements ReadonlyContext, so it can return itself
func (ic *invocationContext) AsReadonly() ReadonlyContext {
	return ic
}
