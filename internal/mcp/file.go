package mcp

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/koopa0/koopa-cli/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerFileTools registers all file operation tools to the MCP server.
// Tools: readFile, writeFile, listFiles, deleteFile, getFileInfo
func (s *Server) registerFileTools() error {
	// readFile
	readFileSchema, err := jsonschema.For[tools.ReadFileInput](nil)
	if err != nil {
		return fmt.Errorf("schema for readFile: %w", err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "readFile",
		Description: "Read the complete content of any text-based file.",
		InputSchema: readFileSchema,
	}, s.ReadFile)

	// writeFile
	writeFileSchema, err := jsonschema.For[tools.WriteFileInput](nil)
	if err != nil {
		return fmt.Errorf("schema for writeFile: %w", err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "writeFile",
		Description: "Write or create any text-based file.",
		InputSchema: writeFileSchema,
	}, s.WriteFile)

	// listFiles
	listFilesSchema, err := jsonschema.For[tools.ListFilesInput](nil)
	if err != nil {
		return fmt.Errorf("schema for listFiles: %w", err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "listFiles",
		Description: "List all files and subdirectories in a directory.",
		InputSchema: listFilesSchema,
	}, s.ListFiles)

	// deleteFile
	deleteFileSchema, err := jsonschema.For[tools.DeleteFileInput](nil)
	if err != nil {
		return fmt.Errorf("schema for deleteFile: %w", err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "deleteFile",
		Description: "Delete a file permanently.",
		InputSchema: deleteFileSchema,
	}, s.DeleteFile)

	// getFileInfo
	getFileInfoSchema, err := jsonschema.For[tools.GetFileInfoInput](nil)
	if err != nil {
		return fmt.Errorf("schema for getFileInfo: %w", err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "getFileInfo",
		Description: "Get detailed metadata about a file.",
		InputSchema: getFileInfoSchema,
	}, s.GetFileInfo)

	return nil
}

// ReadFile handles the readFile MCP tool call.
func (s *Server) ReadFile(ctx context.Context, req *mcp.CallToolRequest, input tools.ReadFileInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.fileToolset.ReadFile(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("readFile failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}

// WriteFile handles the writeFile MCP tool call.
func (s *Server) WriteFile(ctx context.Context, req *mcp.CallToolRequest, input tools.WriteFileInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.fileToolset.WriteFile(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("writeFile failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}

// ListFiles handles the listFiles MCP tool call.
func (s *Server) ListFiles(ctx context.Context, req *mcp.CallToolRequest, input tools.ListFilesInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.fileToolset.ListFiles(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("listFiles failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}

// DeleteFile handles the deleteFile MCP tool call.
func (s *Server) DeleteFile(ctx context.Context, req *mcp.CallToolRequest, input tools.DeleteFileInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.fileToolset.DeleteFile(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("deleteFile failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}

// GetFileInfo handles the getFileInfo MCP tool call.
func (s *Server) GetFileInfo(ctx context.Context, req *mcp.CallToolRequest, input tools.GetFileInfoInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.fileToolset.GetFileInfo(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("getFileInfo failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}
