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
			Details: map[string]any{"field": "path", "reason": "invalid"},
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

	// Should contain "Details:"
	if !contains(textContent.Text, "Details:") {
		t.Errorf("resultToMCP text should contain 'Details:': %s", textContent.Text)
	}
}
