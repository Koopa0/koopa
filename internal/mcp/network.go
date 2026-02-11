package mcp

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/koopa0/koopa/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerNetwork registers all network operation tools to the MCP server.
// Tools: web_search, web_fetch
func (s *Server) registerNetwork() error {
	// web_search
	searchSchema, err := jsonschema.For[tools.SearchInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.WebSearchName, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.WebSearchName,
		Description: "Search the web for information. Returns relevant results with titles, URLs, and content snippets. " +
			"Use this to find current information, news, or facts from the internet.",
		InputSchema: searchSchema,
	}, s.WebSearch)

	// web_fetch
	fetchSchema, err := jsonschema.For[tools.FetchInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.WebFetchName, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.WebFetchName,
		Description: "Fetch and extract content from one or more URLs (max 10). " +
			"Supports HTML pages, JSON APIs, and plain text. " +
			"For HTML: uses Readability algorithm to extract main content. " +
			"Supports parallel fetching with rate limiting. " +
			"Returns extracted content (max 50KB per URL). " +
			"Note: Does not render JavaScript - for SPA pages, content may be incomplete.",
		InputSchema: fetchSchema,
	}, s.WebFetch)

	return nil
}

// WebSearch handles the web_search MCP tool call.
func (s *Server) WebSearch(ctx context.Context, _ *mcp.CallToolRequest, input tools.SearchInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.network.Search(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("searching web: %w", err)
	}

	return dataToMCP(result), nil, nil
}

// WebFetch handles the web_fetch MCP tool call.
func (s *Server) WebFetch(ctx context.Context, _ *mcp.CallToolRequest, input tools.FetchInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.network.Fetch(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching web: %w", err)
	}

	return dataToMCP(result), nil, nil
}
