package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/koopa0/koopa-cli/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server wraps the MCP SDK server and Koopa's Kit
type Server struct {
	mcpServer *mcp.Server
	kit       *tools.Kit
	name      string
	version   string
}

// Config holds MCP server configuration
type Config struct {
	Name      string
	Version   string
	KitConfig tools.KitConfig
}

// NewServer creates a new MCP server
func NewServer(cfg Config) (*Server, error) {
	// Validate config
	if cfg.Name == "" {
		return nil, fmt.Errorf("server name is required")
	}
	if cfg.Version == "" {
		return nil, fmt.Errorf("server version is required")
	}

	// Create Kit
	kit, err := tools.NewKit(cfg.KitConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kit: %w", err)
	}

	// Create MCP server (using official SDK)
	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    cfg.Name,
		Version: cfg.Version,
	}, nil)

	s := &Server{
		mcpServer: mcpServer,
		kit:       kit,
		name:      cfg.Name,
		version:   cfg.Version,
	}

	// Register tools
	if err := s.registerTools(); err != nil {
		return nil, fmt.Errorf("failed to register tools: %w", err)
	}

	return s, nil
}

// Run starts the MCP server on the given transport
// This is a blocking call that handles all MCP protocol communication
func (s *Server) Run(ctx context.Context, transport mcp.Transport) error {
	return s.mcpServer.Run(ctx, transport)
}

// registerTools registers all Kit tools to the MCP server
func (s *Server) registerTools() error {
	// Register file tools
	if err := s.registerReadFile(); err != nil {
		return fmt.Errorf("failed to register readFile: %w", err)
	}

	// TODO: Register other tools in future iterations

	return nil
}

// ReadFileInput defines the input schema for readFile tool
type ReadFileInput struct {
	Path string `json:"path" jsonschema:"The file path to read (absolute or relative)"`
}

// registerReadFile registers the readFile tool
// Following PHASE2-DESIGN-RATIONALE.md:
// Direct handling in the handler (like net/http.Handler)
// NO conversion layer - build MCP response inline
// NO adaptResult(), toResponse(), NewToolResult() functions
func (s *Server) registerReadFile() error {
	// Infer input schema from struct
	inputSchema, err := jsonschema.For[ReadFileInput](nil)
	if err != nil {
		return fmt.Errorf("failed to create input schema: %w", err)
	}

	// Define tool
	tool := &mcp.Tool{
		Name:        "readFile",
		Description: "Read the complete content of any text-based file. Supports absolute and relative paths. Validates paths for security.",
		InputSchema: inputSchema,
	}

	// Register tool with handler
	// Following Go convention: direct inline handling (NO conversion functions)
	mcp.AddTool(s.mcpServer, tool, func(ctx context.Context, req *mcp.CallToolRequest, in ReadFileInput) (*mcp.CallToolResult, any, error) {
		// Call Kit method
		result, err := s.kit.ReadFile(nil, tools.ReadFileInput{Path: in.Path})
		if err != nil {
			// System error - propagate to MCP
			return nil, nil, fmt.Errorf("system error: %w", err)
		}

		// Direct inline handling (NO conversion function)
		// Build MCP response directly here, like net/http.Handler
		if result.Status == tools.StatusError {
			// Agent error - return as error result
			errorText := fmt.Sprintf("Error [%s]: %s", result.Error.Code, result.Error.Message)
			if result.Error.Details != nil {
				detailsJSON, _ := json.Marshal(result.Error.Details)
				errorText += fmt.Sprintf("\nDetails: %s", string(detailsJSON))
			}

			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: errorText}},
				IsError: true,
			}, nil, nil
		}

		// Success - extract content from result.Data
		data, ok := result.Data.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("unexpected data format")
		}

		content, ok := data["content"].(string)
		if !ok {
			return nil, nil, fmt.Errorf("content field not found or not string")
		}

		// Return file content as text
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: content}},
		}, nil, nil
	})

	return nil
}
