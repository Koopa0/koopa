package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/koopa0/koopa-cli/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerNetworkTools registers all network operation tools to the MCP server.
// Tools: web_search, web_fetch
func (s *Server) registerNetworkTools() error {
	// web_search
	searchSchema, err := jsonschema.For[tools.SearchInput](nil)
	if err != nil {
		return fmt.Errorf("schema for web_search: %w", err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "web_search",
		Description: "Search the web for information. Returns relevant results with titles, URLs, and content snippets.",
		InputSchema: searchSchema,
	}, s.WebSearch)

	// web_fetch
	fetchSchema, err := jsonschema.For[tools.FetchInput](nil)
	if err != nil {
		return fmt.Errorf("schema for web_fetch: %w", err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "web_fetch",
		Description: "Fetch and extract content from one or more URLs (max 10). Supports HTML, JSON, and plain text.",
		InputSchema: fetchSchema,
	}, s.WebFetch)

	return nil
}

// WebSearch handles the web_search MCP tool call.
func (s *Server) WebSearch(ctx context.Context, _ *mcp.CallToolRequest, input tools.SearchInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}

	// Access the search method via reflection or direct call
	// Since search is unexported, we need to use the Tools interface
	toolsList, err := s.networkToolset.Tools(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("get tools: %w", err)
	}

	// Find web_search tool
	var searchTool *tools.ExecutableTool
	for _, t := range toolsList {
		if t.Name() == "web_search" {
			if et, ok := t.(*tools.ExecutableTool); ok {
				searchTool = et
				break
			}
		}
	}

	if searchTool == nil {
		return nil, nil, fmt.Errorf("web_search tool not found")
	}

	result, err := searchTool.Execute(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("web_search failed: %w", err)
	}

	return outputToMCP(result), nil, nil
}

// WebFetch handles the web_fetch MCP tool call.
func (s *Server) WebFetch(ctx context.Context, _ *mcp.CallToolRequest, input tools.FetchInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}

	toolsList, err := s.networkToolset.Tools(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("get tools: %w", err)
	}

	// Find web_fetch tool
	var fetchTool *tools.ExecutableTool
	for _, t := range toolsList {
		if t.Name() == "web_fetch" {
			if et, ok := t.(*tools.ExecutableTool); ok {
				fetchTool = et
				break
			}
		}
	}

	if fetchTool == nil {
		return nil, nil, fmt.Errorf("web_fetch tool not found")
	}

	result, err := fetchTool.Execute(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("web_fetch failed: %w", err)
	}

	return outputToMCP(result), nil, nil
}

// outputToMCP converts tool output to MCP result.
func outputToMCP(output any) *mcp.CallToolResult {
	// Convert to JSON for MCP transport
	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error marshaling output: %v", err)}},
			IsError: true,
		}
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(jsonBytes)}},
	}
}
