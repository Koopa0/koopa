package mcp

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/koopa0/koopa/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerNetworkTools registers all network operation tools to the MCP server.
// Tools: web_search, web_fetch
func (s *Server) registerNetworkTools() error {
	// web_search
	searchSchema, err := jsonschema.For[tools.SearchInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.ToolWebSearch, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        tools.ToolWebSearch,
		Description: "Search the web for information. Returns relevant results with titles, URLs, and content snippets.",
		InputSchema: searchSchema,
	}, s.WebSearch)

	// web_fetch
	fetchSchema, err := jsonschema.For[tools.FetchInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.ToolWebFetch, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        tools.ToolWebFetch,
		Description: "Fetch and extract content from one or more URLs (max 10). Supports HTML, JSON, and plain text.",
		InputSchema: fetchSchema,
	}, s.WebFetch)

	return nil
}

// WebSearch handles the web_search MCP tool call.
// Architecture: Direct method call (consistent with file.go and system.go).
func (s *Server) WebSearch(ctx context.Context, _ *mcp.CallToolRequest, input tools.SearchInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}

	// Direct method call - O(1), consistent with FileToolset.ReadFile() pattern
	result, err := s.networkTools.Search(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("web_search failed: %w", err)
	}

	return dataToMCP(result), nil, nil
}

// WebFetch handles the web_fetch MCP tool call.
// Architecture: Direct method call (consistent with file.go and system.go).
func (s *Server) WebFetch(ctx context.Context, _ *mcp.CallToolRequest, input tools.FetchInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}

	// Direct method call - O(1), consistent with FileToolset.ReadFile() pattern
	result, err := s.networkTools.Fetch(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("web_fetch failed: %w", err)
	}

	return dataToMCP(result), nil, nil
}
