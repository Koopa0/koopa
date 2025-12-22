package mcp

import (
	"testing"

	"github.com/koopa0/koopa/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestResultToMCP_Success(t *testing.T) {
	result := tools.Result{
		Status: tools.StatusSuccess,
		Data:   map[string]any{"result": "value", "count": 42},
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

	// Data should be JSON marshaled
	if !contains(textContent.Text, "result") || !contains(textContent.Text, "value") {
		t.Errorf("resultToMCP text should contain JSON data: %s", textContent.Text)
	}
}

func TestResultToMCP_Error(t *testing.T) {
	result := tools.Result{
		Status: tools.StatusError,
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
		Status: tools.StatusError,
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

// =============================================================================
// dataToMCP Tests
// =============================================================================

func TestDataToMCP_ValidData(t *testing.T) {
	data := map[string]any{"key": "value", "count": 42}
	result := dataToMCP(data)

	if result.IsError {
		t.Error("dataToMCP should not set IsError for valid data")
	}

	if len(result.Content) == 0 {
		t.Fatal("dataToMCP returned empty content")
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("dataToMCP content is not TextContent")
	}

	if !contains(textContent.Text, "key") || !contains(textContent.Text, "value") {
		t.Errorf("dataToMCP should contain JSON data: %s", textContent.Text)
	}
}

func TestDataToMCP_NilData(t *testing.T) {
	result := dataToMCP(nil)

	if result.IsError {
		t.Error("dataToMCP should not set IsError for nil data")
	}

	if len(result.Content) == 0 {
		t.Fatal("dataToMCP returned empty content")
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("dataToMCP content is not TextContent")
	}

	// Nil data should return empty string (Rob Pike: "honest zero value")
	if textContent.Text != "" {
		t.Errorf("dataToMCP(nil) should return empty string, got: %q", textContent.Text)
	}
}

func TestDataToMCP_SliceData(t *testing.T) {
	data := []string{"item1", "item2", "item3"}
	result := dataToMCP(data)

	if result.IsError {
		t.Error("dataToMCP should not set IsError for slice data")
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("dataToMCP content is not TextContent")
	}

	if !contains(textContent.Text, "item1") {
		t.Errorf("dataToMCP should contain JSON array: %s", textContent.Text)
	}
}

func TestDataToMCP_NestedStruct(t *testing.T) {
	type Inner struct {
		Value int `json:"value"`
	}
	type Outer struct {
		Name  string `json:"name"`
		Inner Inner  `json:"inner"`
	}

	data := Outer{Name: "test", Inner: Inner{Value: 42}}
	result := dataToMCP(data)

	if result.IsError {
		t.Error("dataToMCP should not set IsError for nested struct")
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("dataToMCP content is not TextContent")
	}

	if !contains(textContent.Text, "test") || !contains(textContent.Text, "42") {
		t.Errorf("dataToMCP should contain nested JSON: %s", textContent.Text)
	}
}

func TestDataToMCP_MarshalError(t *testing.T) {
	// Channels cannot be marshaled to JSON
	data := make(chan int)
	result := dataToMCP(data)

	if !result.IsError {
		t.Error("dataToMCP should set IsError for unmarshalable data")
	}

	if len(result.Content) == 0 {
		t.Fatal("dataToMCP returned empty content")
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("dataToMCP content is not TextContent")
	}

	if textContent.Text != "marshal error" {
		t.Errorf("dataToMCP should return 'marshal error', got: %q", textContent.Text)
	}
}

func TestDataToMCP_ResultNilData(t *testing.T) {
	// Test that resultToMCP with nil Data returns empty string
	result := tools.Result{
		Status: tools.StatusSuccess,
		Data:   nil,
	}

	mcpResult := resultToMCP(result)

	if mcpResult.IsError {
		t.Error("resultToMCP should not set IsError for success with nil data")
	}

	textContent, ok := mcpResult.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("resultToMCP content is not TextContent")
	}

	if textContent.Text != "" {
		t.Errorf("resultToMCP with nil data should return empty string, got: %q", textContent.Text)
	}
}

// =============================================================================
// sanitizeErrorDetails Tests
// =============================================================================

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
