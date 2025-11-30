package mcp

import (
	"testing"

	"github.com/koopa0/koopa-cli/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestResultToMCP_Success(t *testing.T) {
	result := tools.Result{
		Status:  tools.StatusSuccess,
		Message: "Operation completed successfully",
		Data:    map[string]any{"key": "value"},
	}

	mcpResult := resultToMCP(result)

	if mcpResult.IsError {
		t.Error("resultToMCP should not set IsError for success status")
	}

	if len(mcpResult.Content) == 0 {
		t.Fatal("resultToMCP returned empty content")
	}

	textContent, ok := mcpResult.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("resultToMCP content is not TextContent")
	}

	if textContent.Text != result.Message {
		t.Errorf("resultToMCP text = %q, want %q", textContent.Text, result.Message)
	}
}

func TestResultToMCP_Error(t *testing.T) {
	result := tools.Result{
		Status:  tools.StatusError,
		Message: "Operation failed",
		Error: &tools.Error{
			Code:    tools.ErrCodeNotFound,
			Message: "File not found",
		},
	}

	mcpResult := resultToMCP(result)

	if !mcpResult.IsError {
		t.Error("resultToMCP should set IsError for error status")
	}

	if len(mcpResult.Content) == 0 {
		t.Fatal("resultToMCP returned empty content")
	}

	textContent, ok := mcpResult.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("resultToMCP content is not TextContent")
	}

	// Should contain error code and message
	if !contains(textContent.Text, string(tools.ErrCodeNotFound)) {
		t.Errorf("resultToMCP text should contain error code: %s", textContent.Text)
	}

	if !contains(textContent.Text, "File not found") {
		t.Errorf("resultToMCP text should contain error message: %s", textContent.Text)
	}
}

func TestResultToMCP_ErrorWithDetails(t *testing.T) {
	result := tools.Result{
		Status:  tools.StatusError,
		Message: "Operation failed",
		Error: &tools.Error{
			Code:    tools.ErrCodeValidation,
			Message: "Validation error",
			// Use whitelisted fields to ensure Details: appears in output
			Details: map[string]any{"error_code": "VALIDATION_ERROR", "user_message": "invalid path"},
		},
	}

	mcpResult := resultToMCP(result)

	if !mcpResult.IsError {
		t.Error("resultToMCP should set IsError for error status")
	}

	if len(mcpResult.Content) == 0 {
		t.Fatal("resultToMCP returned empty content")
	}

	textContent, ok := mcpResult.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("resultToMCP content is not TextContent")
	}

	// Should contain "Details:" with whitelisted fields
	if !contains(textContent.Text, "Details:") {
		t.Errorf("resultToMCP text should contain 'Details:': %s", textContent.Text)
	}
}

func TestSanitizeErrorDetails(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		wantKeys []string
		noKeys   []string
	}{
		{
			name: "whitelisted fields only",
			input: map[string]any{
				"error_code":   "TOOL_NOT_FOUND",
				"error_type":   "ValidationError",
				"user_message": "Tool not found",
				"request_id":   "req-123",
			},
			wantKeys: []string{"error_code", "error_type", "user_message", "request_id"},
			noKeys:   nil,
		},
		{
			name: "sensitive fields redacted",
			input: map[string]any{
				"error_code": "INTERNAL_ERROR",
				"stack":      "goroutine 1 [running]:\nmain.main()\n\t/path/to/file.go:42",
				"env":        "GEMINI_API_KEY=sk-secret-key",
				"api_key":    "sk-secret-key",
				"password":   "hunter2",
				"path":       "/home/user/secrets/config.json",
			},
			wantKeys: []string{"error_code"},
			noKeys:   []string{"stack", "env", "api_key", "password", "path"},
		},
		{
			name:     "non-map input returns empty",
			input:    "string input",
			wantKeys: nil,
			noKeys:   nil,
		},
		{
			name:     "nil input returns empty",
			input:    nil,
			wantKeys: nil,
			noKeys:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeErrorDetails(tt.input)

			for _, key := range tt.wantKeys {
				if _, ok := result[key]; !ok {
					t.Errorf("sanitizeErrorDetails() missing expected key %q", key)
				}
			}

			for _, key := range tt.noKeys {
				if _, ok := result[key]; ok {
					t.Errorf("sanitizeErrorDetails() should not contain sensitive key %q", key)
				}
			}
		})
	}
}
