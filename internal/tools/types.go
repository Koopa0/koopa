package tools

// Status represents the execution status of a tool.
type Status string

const (
	StatusSuccess Status = "success"
	StatusError   Status = "error"
	StatusPartial Status = "partial"
)

// ErrorCode represents standardized error codes.
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

// Result is the standard return format for all tools.
type Result struct {
	Status  Status `json:"status" jsonschema_description:"The execution status"`
	Message string `json:"message,omitempty" jsonschema_description:"Human-readable message"`
	Data    any    `json:"data,omitempty" jsonschema_description:"The tool's output data"`
	Error   *Error `json:"error,omitempty" jsonschema_description:"Error information if failed"`
}

// Error provides structured error information.
type Error struct {
	Code    ErrorCode `json:"code" jsonschema_description:"Error code"`
	Message string    `json:"message" jsonschema_description:"Detailed error message"`
	Details any       `json:"details,omitempty" jsonschema_description:"Additional error context"`
}
