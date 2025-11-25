package mcp

import (
	"encoding/json"
	"fmt"

	"github.com/koopa0/koopa-cli/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// resultToMCP converts a tools.Result to mcp.CallToolResult.
// This follows the Direct Inline Handling principle but extracts the common pattern.
func resultToMCP(result tools.Result) *mcp.CallToolResult {
	if result.Status == tools.StatusError {
		errorText := fmt.Sprintf("[%s] %s", result.Error.Code, result.Error.Message)
		if result.Error.Details != nil {
			detailsJSON, _ := json.Marshal(result.Error.Details)
			errorText += fmt.Sprintf("\nDetails: %s", string(detailsJSON))
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: errorText}},
			IsError: true,
		}
	}

	// Success - return the message
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result.Message}},
	}
}
