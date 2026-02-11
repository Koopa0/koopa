package mcp

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/koopa0/koopa/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCP Error Detail Whitelist Policy:
// - error_code: Safe (controlled enum, e.g., "TOOL_NOT_FOUND")
// - error_type: Safe (controlled enum, e.g., "ValidationError")
// - user_message: Safe (user-facing message only)
// - request_id: Safe (for support ticket correlation)
//
// NEVER expose:
// - stack traces
// - file paths
// - environment variables
// - internal IDs
// - API keys/tokens
//
// Reference: MCP Protocol error handling best practices

// resultToMCP converts a tools.Result to mcp.CallToolResult.
// This follows the Direct Inline Handling principle but extracts the common pattern.
// If logger is nil, falls back to slog.Default().
func resultToMCP(result tools.Result, logger *slog.Logger) *mcp.CallToolResult {
	if logger == nil {
		logger = slog.Default()
	}

	if result.Status == tools.StatusError {
		errorText := fmt.Sprintf("[%s] %s", result.Error.Code, result.Error.Message)
		if result.Error.Details != nil {
			// Sanitize error details before exposing to clients
			sanitized := sanitizeErrorDetails(result.Error.Details)
			if len(sanitized) > 0 {
				detailsJSON, err := json.Marshal(sanitized)
				if err != nil {
					// Log internal error, don't expose to client
					logger.Warn("marshaling sanitized error details", "error", err)
					errorText += "\nDetails: (see server logs)"
				} else {
					errorText += fmt.Sprintf("\nDetails: %s", string(detailsJSON))
				}
			}

			// Always log full details server-side for debugging
			logger.Debug("MCP error details", "details", result.Error.Details)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: errorText}},
			IsError: true,
		}
	}

	// Success - return data as JSON
	return dataToMCP(result.Data)
}

// dataToMCP converts arbitrary data to MCP text content via JSON marshaling.
// This is the simple, unified approach: all data becomes JSON, clients parse it.
func dataToMCP(data any) *mcp.CallToolResult {
	if data == nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: ""}},
		}
	}

	b, err := json.Marshal(data)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "marshal error"}},
			IsError: true,
		}
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}
}

// sanitizeErrorDetails extracts only safe, whitelisted fields from error details.
// All sensitive information (stack traces, paths, env vars) is redacted.
func sanitizeErrorDetails(details any) map[string]any {
	safe := make(map[string]any)

	// Type-assert to map
	detailsMap, ok := details.(map[string]any)
	if !ok {
		return safe
	}

	// Whitelist of safe fields (expand conservatively)
	safeFields := map[string]bool{
		"error_code":   true, // e.g., "TOOL_NOT_FOUND"
		"error_type":   true, // e.g., "ValidationError"
		"user_message": true, // User-facing message only
		"request_id":   true, // For support correlation
	}

	for key, val := range detailsMap {
		if safeFields[key] {
			safe[key] = val
		}
	}

	return safe
}
