package mcp

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/koopa0/koopa/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerKnowledgeTools registers all knowledge tools to the MCP server.
// Tools: search_history, search_documents, search_system_knowledge, knowledge_store
func (s *Server) registerKnowledgeTools() error {
	searchSchema, err := jsonschema.For[tools.KnowledgeSearchInput](nil)
	if err != nil {
		return fmt.Errorf("schema for knowledge search tools: %w", err)
	}

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.ToolSearchHistory,
		Description: "Search conversation history using semantic similarity. " +
			"Finds past exchanges related to the query.",
		InputSchema: searchSchema,
	}, s.SearchHistory)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.ToolSearchDocuments,
		Description: "Search indexed documents (PDFs, code files, notes) using semantic similarity. " +
			"Finds document sections related to the query.",
		InputSchema: searchSchema,
	}, s.SearchDocuments)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.ToolSearchSystemKnowledge,
		Description: "Search system knowledge base (tool usage, commands, patterns) using semantic similarity. " +
			"Finds internal system documentation and usage patterns.",
		InputSchema: searchSchema,
	}, s.SearchSystemKnowledge)

	storeSchema, err := jsonschema.For[tools.KnowledgeStoreInput](nil)
	if err != nil {
		return fmt.Errorf("schema for knowledge store tool: %w", err)
	}

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.ToolStoreKnowledge,
		Description: "Store a knowledge entry for later retrieval via search_documents. " +
			"Saves important information, notes, or learnings across sessions.",
		InputSchema: storeSchema,
	}, s.StoreKnowledge)

	return nil
}

// SearchHistory handles the search_history MCP tool call.
func (s *Server) SearchHistory(ctx context.Context, _ *mcp.CallToolRequest, input tools.KnowledgeSearchInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.knowledgeTools.SearchHistory(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("searchHistory failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}

// SearchDocuments handles the search_documents MCP tool call.
func (s *Server) SearchDocuments(ctx context.Context, _ *mcp.CallToolRequest, input tools.KnowledgeSearchInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.knowledgeTools.SearchDocuments(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("searchDocuments failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}

// SearchSystemKnowledge handles the search_system_knowledge MCP tool call.
func (s *Server) SearchSystemKnowledge(ctx context.Context, _ *mcp.CallToolRequest, input tools.KnowledgeSearchInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.knowledgeTools.SearchSystemKnowledge(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("searchSystemKnowledge failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}

// StoreKnowledge handles the knowledge_store MCP tool call.
func (s *Server) StoreKnowledge(ctx context.Context, _ *mcp.CallToolRequest, input tools.KnowledgeStoreInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.knowledgeTools.StoreKnowledge(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("storeKnowledge failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}
