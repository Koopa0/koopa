// Package agent provides the agent abstraction layer for AI chat functionality.
package agent

import "errors"

// Sentinel errors for agent operations.
// Only errors that are checked with errors.Is() are defined here.
var (
	// ErrInvalidSession indicates the session ID is invalid or malformed.
	// Used by: web/handlers/chat.go for HTTP status mapping
	ErrInvalidSession = errors.New("invalid session")

	// ErrExecutionFailed indicates agent execution failed.
	// Used by: web/handlers/chat.go for HTTP status mapping
	ErrExecutionFailed = errors.New("execution failed")
)
