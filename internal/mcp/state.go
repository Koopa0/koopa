package mcp

// state.go defines state tracking types for MCP server connections.
//
// Provides type-safe state management for monitoring MCP server health:
//   - Status: Type-safe enum (Disconnected → Connecting → Connected/Failed)
//   - State: Tracks connection status, success/failure counts, last error, timestamps
//
// Used by Server for observability and graceful degradation. Thread-safe via sync.RWMutex.

import "time"

// Status represents the connection status of an MCP server.
type Status string

const (
	// Disconnected indicates the server is not connected.
	Disconnected Status = "disconnected"

	// Connecting indicates a connection attempt is in progress.
	Connecting Status = "connecting"

	// Connected indicates the server is successfully connected.
	Connected Status = "connected"

	// Failed indicates the connection attempt failed.
	Failed Status = "failed"
)

// State tracks the state of a single MCP server connection.
type State struct {
	// Name is the unique identifier for this MCP server.
	Name string

	// Status is the current connection status.
	Status Status

	// LastError is the last error encountered (if any).
	LastError error

	// LastAttempt is the timestamp of the last connection attempt.
	LastAttempt time.Time

	// SuccessCount is the number of successful operations.
	SuccessCount int

	// FailureCount is the number of failed operations.
	FailureCount int
}
