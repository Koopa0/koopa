package tools

// ToolError defines a structured error format for model consumption.
// It allows tools to return specific error types and messages that the model can understand and correct.
type ToolError struct {
	ErrorType string `json:"error_type"` // e.g., "FileNotFound", "PermissionDenied", "InvalidArguments"
	Message   string `json:"message"`
}

// Error implements the error interface.
func (e ToolError) Error() string {
	return e.ErrorType + ": " + e.Message
}
