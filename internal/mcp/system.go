package mcp

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/koopa0/koopa/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerSystem registers all system operation tools to the MCP server.
// Tools: current_time, execute_command, get_env
func (s *Server) registerSystem() error {
	// current_time
	currentTimeSchema, err := jsonschema.For[tools.CurrentTimeInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.CurrentTimeName, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.CurrentTimeName,
		Description: "Get the current system date and time. " +
			"Returns: formatted time string, Unix timestamp, and ISO 8601 format. " +
			"Always returns the server's local time zone.",
		InputSchema: currentTimeSchema,
	}, s.CurrentTime)

	// execute_command
	executeCommandSchema, err := jsonschema.For[tools.ExecuteCommandInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.ExecuteCommandName, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.ExecuteCommandName,
		Description: "Execute a shell command from the allowed list with security validation. " +
			"Allowed commands: ls, pwd, cd, tree, date, whoami, hostname, uname, df, du, free, top, ps, " +
			"git (with subcommand restrictions), go (version/env/vet/doc/fmt/list only), npm/yarn (read-only queries), which, whereis. " +
			"Commands run with a timeout to prevent hanging. " +
			"Returns: stdout, stderr, exit code, and execution time. " +
			"Security: Commands not in the allowlist are blocked. Subcommands are restricted per command.",
		InputSchema: executeCommandSchema,
	}, s.ExecuteCommand)

	// get_env
	getEnvSchema, err := jsonschema.For[tools.GetEnvInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.GetEnvName, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.GetEnvName,
		Description: "Read an environment variable value from the system. " +
			"Returns: the variable name and its value. " +
			"Use this to: check configuration, verify paths, read non-sensitive settings. " +
			"Security: Sensitive variables containing KEY, SECRET, TOKEN, or PASSWORD in their names are protected and will not be returned.",
		InputSchema: getEnvSchema,
	}, s.Env)

	return nil
}

// CurrentTime handles the currentTime MCP tool call.
func (s *Server) CurrentTime(ctx context.Context, _ *mcp.CallToolRequest, input tools.CurrentTimeInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.system.CurrentTime(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("getting current time: %w", err)
	}
	return resultToMCP(result, s.logger), nil, nil
}

// ExecuteCommand handles the executeCommand MCP tool call.
func (s *Server) ExecuteCommand(ctx context.Context, _ *mcp.CallToolRequest, input tools.ExecuteCommandInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.system.ExecuteCommand(toolCtx, input)
	if err != nil {
		// Only infrastructure errors (context cancellation) return Go error
		return nil, nil, fmt.Errorf("executing command: %w", err)
	}
	return resultToMCP(result, s.logger), nil, nil
}

// Env handles the getEnv MCP tool call.
func (s *Server) Env(ctx context.Context, _ *mcp.CallToolRequest, input tools.GetEnvInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.system.Env(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("getting env: %w", err)
	}
	return resultToMCP(result, s.logger), nil, nil
}
