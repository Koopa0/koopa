// Package agent provides common errors for agent operations.
//
// Error Design Philosophy:
// - Use sentinel errors (errors.Is/errors.As) for Go-idiomatic error handling
// - Wrap with context using fmt.Errorf("%w: details", ErrXxx)
// - Domain-specific errors (config, tools) remain in their packages
// - This package provides agent-level errors shared across flows/agents
package agent

import "errors"

// ============================================================================
// Session Errors
// ============================================================================

var (
	// ErrInvalidSession indicates the session ID is invalid or malformed.
	ErrInvalidSession = errors.New("invalid session")

	// ErrSessionNotFound indicates the session does not exist.
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionExpired indicates the session has expired.
	ErrSessionExpired = errors.New("session expired")
)

// ============================================================================
// Execution Errors
// ============================================================================

var (
	// ErrExecutionFailed indicates agent execution failed.
	ErrExecutionFailed = errors.New("execution failed")

	// ErrStreamingFailed indicates streaming output failed.
	ErrStreamingFailed = errors.New("streaming failed")

	// ErrToolExecutionFailed indicates a tool execution failed.
	ErrToolExecutionFailed = errors.New("tool execution failed")

	// ErrMaxTurnsExceeded indicates the agent exceeded maximum allowed turns.
	ErrMaxTurnsExceeded = errors.New("max turns exceeded")
)

// ============================================================================
// Context/Lifecycle Errors
// ============================================================================

var (
	// ErrContextCancelled indicates the operation was cancelled.
	ErrContextCancelled = errors.New("context cancelled")

	// ErrTimeout indicates the operation timed out.
	ErrTimeout = errors.New("operation timeout")

	// ErrShutdown indicates the system is shutting down.
	ErrShutdown = errors.New("shutdown in progress")
)

// ============================================================================
// External Service Errors
// ============================================================================

var (
	// ErrRateLimited indicates the operation was rate limited.
	ErrRateLimited = errors.New("rate limited")

	// ErrModelUnavailable indicates the LLM model is unavailable.
	ErrModelUnavailable = errors.New("model unavailable")

	// ErrNetworkError indicates a network-related error.
	ErrNetworkError = errors.New("network error")

	// ErrServiceUnavailable indicates an external service is unavailable.
	ErrServiceUnavailable = errors.New("service unavailable")
)

// ============================================================================
// Validation Errors
// ============================================================================

var (
	// ErrInvalidInput indicates the input is invalid.
	ErrInvalidInput = errors.New("invalid input")

	// ErrMissingRequired indicates a required field is missing.
	ErrMissingRequired = errors.New("missing required field")
)

// ============================================================================
// Security Errors
// ============================================================================

var (
	// ErrUnauthorized indicates the operation is not authorized.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden indicates the operation is forbidden.
	ErrForbidden = errors.New("forbidden")

	// ErrSecurityViolation indicates a security policy violation.
	ErrSecurityViolation = errors.New("security violation")
)
