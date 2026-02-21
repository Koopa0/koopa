package mcp

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/koopa/internal/tools"
)

// registerFile registers all file operation tools to the MCP server.
// Tools: read_file, write_file, list_files, delete_file, get_file_info
func (s *Server) registerFile() error {
	// read_file
	readFileSchema, err := jsonschema.For[tools.ReadFileInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.ReadFileName, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.ReadFileName,
		Description: "Read the complete content of a text-based file. " +
			"Use this to examine source code, configuration files, logs, or documentation. " +
			"Supports files up to 10MB. Binary files are not supported and will return an error. " +
			"Returns: file path, content (UTF-8), size in bytes, and line count.",
		InputSchema: readFileSchema,
	}, s.ReadFile)

	// write_file
	writeFileSchema, err := jsonschema.For[tools.WriteFileInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.WriteFileName, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.WriteFileName,
		Description: "Write or create a text-based file with the specified content. " +
			"Creates parent directories automatically if they don't exist. " +
			"Overwrites existing files without confirmation. " +
			"Returns: file path, bytes written, whether file was created or updated.",
		InputSchema: writeFileSchema,
	}, s.WriteFile)

	// list_files
	listFilesSchema, err := jsonschema.For[tools.ListFilesInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.ListFilesName, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.ListFilesName,
		Description: "List files and subdirectories in a directory. " +
			"Returns file names, sizes, types (file/directory), and modification times. " +
			"Does not recurse into subdirectories.",
		InputSchema: listFilesSchema,
	}, s.ListFiles)

	// delete_file
	deleteFileSchema, err := jsonschema.For[tools.DeleteFileInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.DeleteFileName, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.DeleteFileName,
		Description: "Permanently delete a file or empty directory. " +
			"WARNING: This action cannot be undone. " +
			"Only deletes empty directories.",
		InputSchema: deleteFileSchema,
	}, s.DeleteFile)

	// get_file_info
	getFileInfoSchema, err := jsonschema.For[tools.FileInfoInput](nil)
	if err != nil {
		return fmt.Errorf("schema for %s: %w", tools.FileInfoName, err)
	}
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: tools.FileInfoName,
		Description: "Get detailed metadata about a file without reading its contents. " +
			"Returns: file size, modification time, permissions, and type (file/directory). " +
			"More efficient than read_file when you only need metadata.",
		InputSchema: getFileInfoSchema,
	}, s.FileInfo)

	return nil
}

// ReadFile handles the readFile MCP tool call.
func (s *Server) ReadFile(ctx context.Context, _ *mcp.CallToolRequest, input tools.ReadFileInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.file.ReadFile(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("reading file: %w", err)
	}

	return resultToMCP(result, s.logger), nil, nil
}

// WriteFile handles the writeFile MCP tool call.
func (s *Server) WriteFile(ctx context.Context, _ *mcp.CallToolRequest, input tools.WriteFileInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.file.WriteFile(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("writing file: %w", err)
	}

	return resultToMCP(result, s.logger), nil, nil
}

// ListFiles handles the listFiles MCP tool call.
func (s *Server) ListFiles(ctx context.Context, _ *mcp.CallToolRequest, input tools.ListFilesInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.file.ListFiles(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("listing files: %w", err)
	}

	return resultToMCP(result, s.logger), nil, nil
}

// DeleteFile handles the deleteFile MCP tool call.
func (s *Server) DeleteFile(ctx context.Context, _ *mcp.CallToolRequest, input tools.DeleteFileInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.file.DeleteFile(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("deleting file: %w", err)
	}

	return resultToMCP(result, s.logger), nil, nil
}

// FileInfo handles the getFileInfo MCP tool call.
func (s *Server) FileInfo(ctx context.Context, _ *mcp.CallToolRequest, input tools.FileInfoInput) (*mcp.CallToolResult, any, error) {
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := s.file.FileInfo(toolCtx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("getting file info: %w", err)
	}

	return resultToMCP(result, s.logger), nil, nil
}
