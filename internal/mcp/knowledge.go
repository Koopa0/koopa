package mcp

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/koopa/internal/tools"
)

// registerKnowledge registers all knowledge tools to the MCP server.
// Tools: search_history, search_documents, search_system_knowledge, knowledge_store
func (s *Server) registerKnowledge() error {
	searchSchema, err := jsonschema.For[tools.KnowledgeSearchInput](nil)
	if err != nil {
		return fmt.Errorf("schema for knowledge search tools: %w", err)
	}

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.SearchHistoryName,
		Description: "Search conversation history using semantic similarity. " +
			"Finds past exchanges that are conceptually related to the query. " +
			"Returns: matched conversation turns with timestamps and similarity scores. " +
			"Use this to: recall past discussions, find context from earlier conversations. " +
			"Default topK: 3. Maximum topK: 10.",
		InputSchema: searchSchema,
	}, s.SearchHistory)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.SearchDocumentsName,
		Description: "Search indexed documents (PDFs, code files, notes) using semantic similarity. " +
			"Finds document sections that are conceptually related to the query. " +
			"Returns: document titles, content excerpts, and similarity scores. " +
			"Use this to: find relevant documentation, locate code examples, research topics. " +
			"Default topK: 5. Maximum topK: 10.",
		InputSchema: searchSchema,
	}, s.SearchDocuments)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.SearchSystemKnowledgeName,
		Description: "Search system knowledge base (tool usage, commands, patterns) using semantic similarity. " +
			"Finds internal system documentation and usage patterns. " +
			"Returns: knowledge entries with descriptions and examples. " +
			"Use this to: understand tool capabilities, find command syntax, learn system patterns. " +
			"Default topK: 3. Maximum topK: 10.",
		InputSchema: searchSchema,
	}, s.SearchSystemKnowledge)

	// Register knowledge_store only when DocStore is available.
	if s.knowledge.HasDocStore() {
		storeSchema, err := jsonschema.For[tools.KnowledgeStoreInput](nil)
		if err != nil {
			return fmt.Errorf("schema for knowledge store tool: %w", err)
		}

		mcp.AddTool(s.mcpServer, &mcp.Tool{
			Name: tools.StoreKnowledgeName,
			Description: "Store a knowledge entry for later retrieval via search_documents. " +
				"Use this to save important information, notes, or learnings " +
				"that the user wants to remember across sessions. " +
				"Each entry gets a unique ID and is indexed for semantic search.",
			InputSchema: storeSchema,
		}, s.StoreKnowledge)
	}

	return nil
}

// SearchHistory handles the search_history MCP tool call.
func (s *Server) SearchHistory(ctx context.Context, _ *mcp.CallToolRequest, input tools.KnowledgeSearchInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.knowledge.SearchHistory(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("searching history: %w", err)
	}

	return resultToMCP(result, s.logger), nil, nil
}

// SearchDocuments handles the search_documents MCP tool call.
func (s *Server) SearchDocuments(ctx context.Context, _ *mcp.CallToolRequest, input tools.KnowledgeSearchInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.knowledge.SearchDocuments(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("searching documents: %w", err)
	}

	return resultToMCP(result, s.logger), nil, nil
}

// SearchSystemKnowledge handles the search_system_knowledge MCP tool call.
func (s *Server) SearchSystemKnowledge(ctx context.Context, _ *mcp.CallToolRequest, input tools.KnowledgeSearchInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.knowledge.SearchSystemKnowledge(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("searching system knowledge: %w", err)
	}

	return resultToMCP(result, s.logger), nil, nil
}

// StoreKnowledge handles the knowledge_store MCP tool call.
func (s *Server) StoreKnowledge(ctx context.Context, _ *mcp.CallToolRequest, input tools.KnowledgeStoreInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.knowledge.StoreKnowledge(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("storing knowledge: %w", err)
	}

	return resultToMCP(result, s.logger), nil, nil
}
