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
// Tools: current_time, execute_command, get_env
func (s *Server) registerSystemTools() error {
	// current_time
	currentTimeSchema, err := jsonschema.For[tools.CurrentTimeInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.ToolCurrentTime, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        tools.ToolCurrentTime,
		Description: "Get the current system date and time in formatted string.",
		InputSchema: currentTimeSchema,
	}, s.CurrentTime)

	// execute_command
	executeCommandSchema, err := jsonschema.For[tools.ExecuteCommandInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.ToolExecuteCommand, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        tools.ToolExecuteCommand,
		Description: "Execute a shell command with security validation. Dangerous commands (rm -rf, sudo, etc.) are blocked.",
		InputSchema: executeCommandSchema,
	}, s.ExecuteCommand)

	// get_env
	getEnvSchema, err := jsonschema.For[tools.GetEnvInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.ToolGetEnv, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        tools.ToolGetEnv,
		Description: "Read an environment variable value. Sensitive variables (*KEY*, *SECRET*, *TOKEN*) are protected.",
		InputSchema: getEnvSchema,
	}, s.GetEnv)

	return nil
}

// CurrentTime handles the currentTime MCP tool call.
func (s *Server) CurrentTime(ctx context.Context, _ *mcp.CallToolRequest, input tools.CurrentTimeInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.systemTools.CurrentTime(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("currentTime failed: %w", err)
	}
	return resultToMCP(result), nil, nil
}

// ExecuteCommand handles the executeCommand MCP tool call.
func (s *Server) ExecuteCommand(ctx context.Context, _ *mcp.CallToolRequest, input tools.ExecuteCommandInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.systemTools.ExecuteCommand(toolCtx, input)
	if err != nil {
		// Only infrastructure errors (context cancellation) return Go error
		return nil, nil, fmt.Errorf("executeCommand failed: %w", err)
	}
	return resultToMCP(result), nil, nil
}

// GetEnv handles the getEnv MCP tool call.
func (s *Server) GetEnv(ctx context.Context, _ *mcp.CallToolRequest, input tools.GetEnvInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.systemTools.GetEnv(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("getEnv failed: %w", err)
	}
	return resultToMCP(result), nil, nil
}
