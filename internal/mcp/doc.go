// Package mcp implements a Model Context Protocol (MCP) server.
//
// The MCP server exposes Koopa's tool capabilities via the Model Context Protocol,
// enabling integration with Cursor, Claude Code, and other MCP clients.
// This allows external LLM tools to call Koopa's tools (file operations, system commands, etc.)
// through a standardized protocol interface.
//
// # Architecture
//
// The MCP server follows a handler-based architecture:
//
//	MCP Client (Cursor, Claude Code, etc.)
//	     |
//	     | (MCP protocol over stdio)
//	     |
//	     v
//	Server (MCP SDK)
//	     |
//	     +-- Tool Registry (maps tool names to handlers)
//	     |
//	     +-- Handler Methods (ReadFile, WriteFile, ExecuteCommand, ...)
//	     |
//	     v
//	Toolsets (File, System, Network, Knowledge)
//	     |
//	     v
//	Execution Results
//
// # Supported Tools
//
// File tools (5): read_file, write_file, list_files, delete_file, get_file_info
//
// System tools (3): current_time, execute_command, get_env
//
// Network tools (2): web_search, web_fetch
//
// Knowledge tools (3-4, optional): search_history, search_documents, search_system_knowledge, knowledge_store
//
// # Tool Handler Pattern
//
// Each tool handler:
//  1. Receives typed input (auto-deserialized by MCP SDK via jsonschema)
//  2. Creates an ai.ToolContext wrapping the request context
//  3. Delegates to the corresponding Toolset method
//  4. Converts the Result to MCP format via resultToMCP
//
// # Security
//
// The MCP server enforces several security measures:
//
//   - Path validation: Prevents directory traversal and symlink escapes
//   - Command whitelist: Only allows explicitly whitelisted commands
//   - SSRF protection: Blocks private networks, cloud metadata endpoints
//   - Environment protection: Blocks sensitive variable names
//   - Input validation: Validates all input parameters
//
// # Error Handling
//
// The MCP server distinguishes between two types of errors:
//
//   - Go errors: Infrastructure failures (context canceled, transport errors).
//     Returned as MCP protocol errors.
//
//   - Tool errors: Validation failures or execution errors.
//     Returned as successful MCP responses with IsError=true,
//     allowing clients to handle errors gracefully.
//
// # Thread Safety
//
// The MCP server is safe for concurrent use. The underlying transport and
// message handling is managed by the MCP SDK.
package mcp
