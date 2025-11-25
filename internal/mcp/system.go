package mcp

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/koopa0/koopa-cli/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerSystemTools registers all system operation tools to the MCP server.
// Tools: currentTime, executeCommand, getEnv
func (s *Server) registerSystemTools() error {
	// currentTime
	currentTimeSchema, err := jsonschema.For[tools.CurrentTimeInput](nil)
	if err != nil {
		return fmt.Errorf("schema for currentTime: %w", err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "currentTime",
		Description: "Get the current system date and time in formatted string.",
		InputSchema: currentTimeSchema,
	}, s.CurrentTime)

	// executeCommand
	executeCommandSchema, err := jsonschema.For[tools.ExecuteCommandInput](nil)
	if err != nil {
		return fmt.Errorf("schema for executeCommand: %w", err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "executeCommand",
		Description: "Execute a shell command with security validation. Dangerous commands (rm -rf, sudo, etc.) are blocked.",
		InputSchema: executeCommandSchema,
	}, s.ExecuteCommand)

	// getEnv
	getEnvSchema, err := jsonschema.For[tools.GetEnvInput](nil)
	if err != nil {
		return fmt.Errorf("schema for getEnv: %w", err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "getEnv",
		Description: "Read an environment variable value. Sensitive variables (*KEY*, *SECRET*, *TOKEN*) are protected.",
		InputSchema: getEnvSchema,
	}, s.GetEnv)

	return nil
}

// CurrentTime handles the currentTime MCP tool call.
func (s *Server) CurrentTime(ctx context.Context, req *mcp.CallToolRequest, input tools.CurrentTimeInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	output, err := s.systemToolset.CurrentTime(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("currentTime failed: %w", err)
	}

	// CurrentTime returns a direct output, not Result
	text := fmt.Sprintf("Current time: %s (Unix: %d, ISO8601: %s)",
		output.Time, output.Timestamp, output.ISO8601)

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, nil, nil
}

// ExecuteCommand handles the executeCommand MCP tool call.
func (s *Server) ExecuteCommand(ctx context.Context, req *mcp.CallToolRequest, input tools.ExecuteCommandInput) (*mcp.CallToolResult, any, error) {
	// Create ToolContext with the MCP context for cancellation support
	toolCtx := &ai.ToolContext{Context: ctx}
	output, err := s.systemToolset.ExecuteCommand(toolCtx, input)
	if err != nil {
		// ExecuteCommand returns error for both dangerous commands and execution failures
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
			IsError: true,
		}, nil, nil
	}

	// Format output
	text := output.Output
	if !output.Success {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: text}},
			IsError: true,
		}, nil, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, nil, nil
}

// GetEnv handles the getEnv MCP tool call.
func (s *Server) GetEnv(ctx context.Context, req *mcp.CallToolRequest, input tools.GetEnvInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	output, err := s.systemToolset.GetEnv(toolCtx, input)
	if err != nil {
		// GetEnv returns error for sensitive variables
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
			IsError: true,
		}, nil, nil
	}

	var text string
	if output.IsSet {
		text = fmt.Sprintf("%s=%s", output.Key, output.Value)
	} else {
		text = fmt.Sprintf("%s is not set", output.Key)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, nil, nil
}
