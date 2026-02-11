// Package tools provides AI agent tools for file, system, network, and knowledge operations.
//
// # Overview
//
// This package implements tools that allow AI agents to interact with the system.
// All tools include built-in security validations and return structured results
// for consistent LLM handling.
//
// # Architecture
//
// Tools are organized into four categories:
//
//   - File: File operations (read, write, list, delete, info)
//   - System: System operations (time, command execution, environment)
//   - Network: Network operations (web search, web fetch)
//   - Knowledge: Knowledge base operations (semantic search)
//
// Each tool struct is created with a constructor, then registered with Genkit.
//
// # Available Tools
//
// File tools (File):
//   - read_file: Read file contents (max 10MB)
//   - write_file: Write or create files
//   - list_files: List directory contents
//   - delete_file: Delete a file
//   - get_file_info: Get file metadata
//
// System tools (System):
//   - current_time: Get current system time
//   - execute_command: Execute shell commands (whitelist enforced)
//   - get_env: Read environment variables (secrets protected)
//
// Network tools (Network):
//   - web_search: Search via SearXNG
//   - web_fetch: Fetch web content with SSRF protection
//
// Knowledge tools (Knowledge):
//   - search_history: Search conversation history
//   - search_documents: Search indexed documents
//   - search_system_knowledge: Search system knowledge base
//   - knowledge_store: Store knowledge documents (when DocStore is available)
//
// # Security
//
// All tools integrate security validators from the security package:
//   - Path validation prevents directory traversal attacks (CWE-22)
//   - Command validation blocks dangerous commands like rm -rf (CWE-78)
//   - SSRF protection blocks private IPs and cloud metadata endpoints
//   - Environment variable protection blocks *KEY*, *SECRET*, *TOKEN* patterns
//
// # Result Type
//
// File, System, and Knowledge tools return the unified Result type.
// Network tools (Search, Fetch) use typed output structs (SearchOutput, FetchOutput)
// with an Error string field for LLM-facing business errors.
//
//	type Result struct {
//	    Status  Status  // StatusSuccess or StatusError
//	    Data    any     // Tool output data
//	    Error   *Error  // Structured error (nil on success)
//	}
//
// Results are constructed using struct literals directly:
//
//	// Success
//	return Result{Status: StatusSuccess, Data: map[string]any{"path": path}}, nil
//
//	// Error
//	return Result{Status: StatusError, Error: &Error{Code: ErrCodeSecurity, Message: "blocked"}}, nil
//
// # Error Handling
//
// Tools distinguish between business errors and infrastructure errors:
//
// Business errors are returned in Result.Error with err = nil:
//   - Security validation failures (blocked path, dangerous command)
//   - Resource not found
//   - Permission denied
//   - Invalid input
//
// Infrastructure errors are returned as Go errors:
//   - Context cancellation
//   - System failures
//
// This allows the LLM to handle expected error conditions gracefully.
//
// # Event Emission
//
// Tools support lifecycle events for SSE streaming via the WithEvents wrapper:
//
//	wrapped := WithEvents("tool_name", handler)
//
// Events emitted:
//   - OnToolStart: Before tool execution begins
//   - OnToolComplete: After successful execution
//   - OnToolError: After execution returns Go error
//
// # Usage Example
//
//	// Create tools with security validators
//	pathVal, _ := security.NewPath([]string{"/allowed/path"})
//	fileTools, err := tools.NewFile(pathVal, logger)
//	if err != nil {
//	    return err
//	}
//
//	// Register with Genkit
//	fileToolList, _ := tools.RegisterFile(g, fileTools)
package tools
