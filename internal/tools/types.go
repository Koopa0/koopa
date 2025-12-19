// Package tools provides tool types and result helpers for agent tool operations.
//
// Error Handling:
//   - All tools return Result with structured error information
//   - Business errors (validation, not found, etc.) use Result.Error
//   - Only infrastructure errors (context cancellation) return Go error
package tools

// ============================================================================
// Status and ErrorCode (for JSON responses to LLM)
// ============================================================================

// Status represents the execution status of a tool.
type Status string

// Tool execution status constants.
const (
	StatusSuccess Status = "success" // Tool completed successfully
	StatusError   Status = "error"   // Tool failed with an error
)

// ErrorCode represents standardized error codes for LLM-facing JSON responses.
// These are kept for backward compatibility and structured LLM responses.
type ErrorCode string

// Standardized error codes for tool responses.
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
	Status Status `json:"status" jsonschema_description:"The execution status"`
	Data   any    `json:"data,omitempty" jsonschema_description:"The tool's output data"`
	Error  *Error `json:"error,omitempty" jsonschema_description:"Error information if failed"`
}

// Error provides structured error information for JSON responses.
type Error struct {
	Code    ErrorCode `json:"code" jsonschema_description:"Error code"`
	Message string    `json:"message" jsonschema_description:"Detailed error message"`
	Details any       `json:"details,omitempty" jsonschema_description:"Additional error context"`
}
