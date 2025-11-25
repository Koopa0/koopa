// Package agent provides the Agent interface and implementations.
package agent

import "context"

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

// NewSessionID creates a new SessionID with validation
func NewSessionID(id string) SessionID {
	if id == "" {
		panic("session ID cannot be empty")
	}
	if len(id) > 255 {
		panic("session ID too long (max 255)")
	}
	return SessionID(id)
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

// Implementation of InvocationContext interface
func (ic *invocationContext) InvocationID() string { return ic.invocationID }
func (ic *invocationContext) Branch() string       { return ic.branch }
func (ic *invocationContext) SessionID() SessionID { return ic.sessionID }
func (ic *invocationContext) AgentName() string    { return ic.agentName }

// AsReadonly returns a read-only version
// invocationContext already implements ReadonlyContext, so it can return itself
func (ic *invocationContext) AsReadonly() ReadonlyContext {
	return ic
}
