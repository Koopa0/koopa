// Package tools provides tool types and errors for agent tool operations.
//
// Error Handling:
//   - Uses sentinel errors for Go-idiomatic error checking with errors.Is()
//   - ErrorCode constants remain for structured JSON responses to LLM
//   - Wrap with context using fmt.Errorf("%w: details", ErrXxx)
package tools

import "errors"

// ============================================================================
// Sentinel Errors
// ============================================================================

var (
	// ErrToolSecurity indicates a security validation failure.
	ErrToolSecurity = errors.New("security error")

	// ErrToolNotFound indicates the requested resource was not found.
	ErrToolNotFound = errors.New("not found")

	// ErrToolPermission indicates a permission denied error.
	ErrToolPermission = errors.New("permission denied")

	// ErrToolIO indicates an I/O operation failed.
	ErrToolIO = errors.New("I/O error")

	// ErrToolExecution indicates tool execution failed.
	ErrToolExecution = errors.New("execution error")

	// ErrToolTimeout indicates the operation timed out.
	ErrToolTimeout = errors.New("timeout error")

	// ErrToolNetwork indicates a network operation failed.
	ErrToolNetwork = errors.New("network error")

	// ErrToolValidation indicates input validation failed.
	ErrToolValidation = errors.New("validation error")

	// ErrToolRateLimit indicates rate limit exceeded.
	ErrToolRateLimit = errors.New("rate limit exceeded")

	// ErrToolUnsupported indicates an unsupported operation.
	ErrToolUnsupported = errors.New("unsupported operation")
)

// ============================================================================
// Status and ErrorCode (for JSON responses to LLM)
// ============================================================================

// Status represents the execution status of a tool.
type Status string

const (
	StatusSuccess Status = "success"
	StatusError   Status = "error"
	StatusPartial Status = "partial"
)

// ErrorCode represents standardized error codes for LLM-facing JSON responses.
// These are kept for backward compatibility and structured LLM responses.
type ErrorCode string

const (
	ErrCodeSecurity   ErrorCode = "SecurityError"
	ErrCodeNotFound   ErrorCode = "NotFound"
	ErrCodePermission ErrorCode = "PermissionDenied"
	ErrCodeIO         ErrorCode = "IOError"
	ErrCodeExecution  ErrorCode = "ExecutionError"
	ErrCodeTimeout    ErrorCode = "TimeoutError"
	ErrCodeNetwork    ErrorCode = "NetworkError"
	ErrCodeValidation ErrorCode = "ValidationError"
)

// ============================================================================
// Result Types (for structured JSON responses)
// ============================================================================

// Result is the standard return format for all tools.
type Result struct {
	Status  Status `json:"status" jsonschema_description:"The execution status"`
	Message string `json:"message,omitempty" jsonschema_description:"Human-readable message"`
	Data    any    `json:"data,omitempty" jsonschema_description:"The tool's output data"`
	Error   *Error `json:"error,omitempty" jsonschema_description:"Error information if failed"`
}

// Error provides structured error information for JSON responses.
type Error struct {
	Code    ErrorCode `json:"code" jsonschema_description:"Error code"`
	Message string    `json:"message" jsonschema_description:"Detailed error message"`
	Details any       `json:"details,omitempty" jsonschema_description:"Additional error context"`
}
