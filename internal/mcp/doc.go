// Package mcp implements a Model Context Protocol (MCP) server.
//
// The MCP server exposes Koopa's tool capabilities via the Model Context Protocol,
// enabling integration with Genkit CLI, Cursor, Claude Code, and other MCP clients.
// This allows external LLM tools to call Koopa's tools (file operations, system commands, etc.)
// through a standardized protocol interface.
//
// # Overview
//
// MCP is a protocol for exposing tools and resources to language models and AI assistants.
// The mcp package implements the server-side protocol handler that:
//
//   - Accepts MCP protocol requests from clients
//   - Translates requests to Koopa's internal tool format
//   - Executes the requested operations
//   - Returns results in MCP protocol format
//
// # Architecture
//
// The MCP server follows a handler-based architecture:
//
//	MCP Client (Genkit CLI, Cursor, etc.)
//	     |
//	     | (MCP protocol over stdio/HTTP)
//	     |
//	     v
//	Server (MCP SDK)
//	     |
//	     +-- Tool Registry (maps tool names to handlers)
//	     |
//	     +-- Handler Chain
//	     |    |
//	     |    +-- readFile handler
//	     |    +-- Other tool handlers (future)
//	     |
//	     v
//	Toolsets (File, System, Network, etc.)
//	     |
//	     v
//	Execution Results
//
// # Supported Tools
//
// Currently, the MCP server supports:
//
//   - readFile: Read file contents with path validation and security checks
//
// Additional tools can be registered by adding handler methods following the
// pattern established by registerReadFile.
//
// # Tool Handler Pattern
//
// Tool handlers follow Go's net/http.Handler pattern for simplicity and consistency:
//
//  1. Define input schema struct with JSON tags and descriptions
//  2. Infer JSON schema using jsonschema-go
//  3. Create mcp.Tool with name, description, and schema
//  4. Register handler using mcp.AddTool with inline logic
//  5. No conversion functions - build responses directly
//
// This approach keeps code simple and maintainable, following Go conventions.
//
// # Security
//
// The MCP server enforces several security measures:
//
//   - Path validation: Prevents directory traversal and symlink escapes
//   - File type restrictions: Only allows text-based files
//   - Error handling: Sanitizes error messages before returning to clients
//   - Input validation: Validates all input parameters
//
// Tools like readFile are designed to be safe for untrusted clients by
// restricting operations to safe directories and file types.
//
// # Integration with Genkit CLI
//
// The MCP server can be launched via Genkit CLI's MCP integration:
//
//	genkit run -- <your-mcp-server>
//
// This makes all registered tools available within Genkit flows and the CLI interface.
//
// # Example Usage
//
//	package main
//
//	import (
//	    "context"
//	    "github.com/koopa0/koopa-cli/internal/mcp"
//	    "github.com/koopa0/koopa-cli/internal/tools"
//	    "github.com/modelcontextprotocol/go-sdk/mcp"
//	    "os"
//	)
//
//	func main() {
//	    ctx := context.Background()
//
//	    // Create file toolset
//	    fileToolset := tools.NewFileToolset(nil)
//
//	    // Create MCP server
//	    server, err := mcp.NewServer(mcp.Config{
//	        Name:        "koopa",
//	        Version:     "1.0.0",
//	        FileToolset: fileToolset,
//	    })
//	    if err != nil {
//	        panic(err)
//	    }
//
//	    // Use stdio transport (standard for MCP servers)
//	    transport := mcp.NewStdioServerTransport()
//
//	    // Run server (blocking)
//	    if err := server.Run(ctx, transport); err != nil {
//	        panic(err)
//	    }
//	}
//
// # Extending with More Tools
//
// To add new tools to the MCP server:
//
//  1. Create a handler function following the readFile pattern
//  2. Add it to registerTools()
//  3. Use mcp.AddTool to register with the SDK
//  4. Ensure proper error handling and validation
//
// Example structure for a new tool:
//
//	type NewToolInput struct {
//	    Param string `json:"param" jsonschema:"Description of param"`
//	}
//
//	func (s *Server) registerNewTool() error {
//	    inputSchema, _ := jsonschema.For[NewToolInput](nil)
//	    tool := &mcp.Tool{
//	        Name:        "newTool",
//	        Description: "Description",
//	        InputSchema: inputSchema,
//	    }
//
//	    mcp.AddTool(s.mcpServer, tool, func(ctx context.Context,
//	        req *mcp.CallToolRequest, in NewToolInput) (*mcp.CallToolResult, any, error) {
//	        // Implementation
//	    })
//	    return nil
//	}
//
// # Error Handling
//
// The MCP server distinguishes between two types of errors:
//
//   - System errors: Implementation bugs or resource exhaustion
//     Return as MCP protocol error (non-2xx status)
//
//   - Agent errors: Tool validation failures or user mistakes
//     Return as successful response with error content and IsError=true
//     This allows clients to handle errors gracefully
//
// # Thread Safety
//
// The MCP server is safe for concurrent use. The underlying transport and
// message handling is managed by the MCP SDK.
package mcp
