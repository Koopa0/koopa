package tools

// ToolError defines a structured error format for model consumption.
// It allows tools to return specific error types and messages that the model can understand and correct.
type ToolError struct {
	ErrorType string `json:"error_type"` // e.g., "FileNotFound", "PermissionDenied", "InvalidArguments"
	Message   string `json:"message"`
}

// Error implements the error interface.
// Uses pointer receiver to avoid unnecessary copying and ensure consistency.
func (e *ToolError) Error() string {
	if e == nil {
		return "<nil ToolError>"
	}
	if e.ErrorType == "" && e.Message == "" {
		return "<empty ToolError>"
	}
	if e.ErrorType == "" {
		return e.Message
	}
	if e.Message == "" {
		return e.ErrorType
	}
	return e.ErrorType + ": " + e.Message
}
