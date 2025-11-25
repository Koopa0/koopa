package mcp

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/koopa0/koopa-cli/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerNetworkTools registers all network operation tools to the MCP server.
// Tools: httpGet
func (s *Server) registerNetworkTools() error {
	// httpGet
	httpGetSchema, err := jsonschema.For[tools.HTTPGetInput](nil)
	if err != nil {
		return fmt.Errorf("schema for httpGet: %w", err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "httpGet",
		Description: "Send an HTTP GET request to a URL. Includes SSRF protection (blocks private IPs, localhost, cloud metadata).",
		InputSchema: httpGetSchema,
	}, s.HTTPGet)

	return nil
}

// HTTPGet handles the httpGet MCP tool call.
func (s *Server) HTTPGet(ctx context.Context, req *mcp.CallToolRequest, input tools.HTTPGetInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.networkToolset.HTTPGet(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("httpGet failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}
