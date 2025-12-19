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
// Tools: read_file, write_file, list_files, delete_file, get_file_info
func (s *Server) registerFileTools() error {
	// read_file
	readFileSchema, err := jsonschema.For[tools.ReadFileInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.ToolReadFile, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        tools.ToolReadFile,
		Description: "Read the complete content of any text-based file.",
		InputSchema: readFileSchema,
	}, s.ReadFile)

	// write_file
	writeFileSchema, err := jsonschema.For[tools.WriteFileInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.ToolWriteFile, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        tools.ToolWriteFile,
		Description: "Write or create any text-based file.",
		InputSchema: writeFileSchema,
	}, s.WriteFile)

	// list_files
	listFilesSchema, err := jsonschema.For[tools.ListFilesInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.ToolListFiles, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        tools.ToolListFiles,
		Description: "List all files and subdirectories in a directory.",
		InputSchema: listFilesSchema,
	}, s.ListFiles)

	// delete_file
	deleteFileSchema, err := jsonschema.For[tools.DeleteFileInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.ToolDeleteFile, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        tools.ToolDeleteFile,
		Description: "Delete a file permanently.",
		InputSchema: deleteFileSchema,
	}, s.DeleteFile)

	// get_file_info
	getFileInfoSchema, err := jsonschema.For[tools.GetFileInfoInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.ToolGetFileInfo, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        tools.ToolGetFileInfo,
		Description: "Get detailed metadata about a file.",
		InputSchema: getFileInfoSchema,
	}, s.GetFileInfo)

	return nil
}

// ReadFile handles the readFile MCP tool call.
func (s *Server) ReadFile(ctx context.Context, _ *mcp.CallToolRequest, input tools.ReadFileInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.fileTools.ReadFile(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("readFile failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}

// WriteFile handles the writeFile MCP tool call.
func (s *Server) WriteFile(ctx context.Context, _ *mcp.CallToolRequest, input tools.WriteFileInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.fileTools.WriteFile(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("writeFile failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}

// ListFiles handles the listFiles MCP tool call.
func (s *Server) ListFiles(ctx context.Context, _ *mcp.CallToolRequest, input tools.ListFilesInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.fileTools.ListFiles(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("listFiles failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}

// DeleteFile handles the deleteFile MCP tool call.
func (s *Server) DeleteFile(ctx context.Context, _ *mcp.CallToolRequest, input tools.DeleteFileInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.fileTools.DeleteFile(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("deleteFile failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}

// GetFileInfo handles the getFileInfo MCP tool call.
func (s *Server) GetFileInfo(ctx context.Context, _ *mcp.CallToolRequest, input tools.GetFileInfoInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.fileTools.GetFileInfo(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("getFileInfo failed: %w", err)
	}

	return resultToMCP(result), nil, nil
}
