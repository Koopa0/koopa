// Package tools provides a modular toolset architecture for AI agents.
//
// # Overview
//
// This package implements an extensible tool system that allows AI agents to
// interact with files, system commands, network resources, and knowledge bases.
// All tools follow a consistent interface pattern and include built-in security
// validations.
//
// # Architecture
//
// The package is organized around the Toolset interface:
//
//	type Toolset interface {
//	    Name() string
//	    Tools(ctx agent.ReadonlyContext) ([]Tool, error)
//	}
//
// Each toolset encapsulates related functionality:
//   - FileToolset: File operations (read_file, write_file, list_directory, delete_file, get_file_info)
//   - SystemToolset: System operations (get_current_time, run_command, get_env)
//   - NetworkToolset: Network operations (web_search, web_fetch) with SSRF protection
//   - KnowledgeToolset: Knowledge base operations (knowledge_search)
//
// # Available Tools
//
// File tools:
//   - read_file: Read file contents
//   - write_file: Write content to a file
//   - list_directory: List directory contents
//   - delete_file: Delete a file
//   - get_file_info: Get file metadata
//
// System tools:
//   - get_current_time: Get current timestamp
//   - run_command: Execute shell commands (with whitelist validation)
//   - get_env: Get environment variables (with secrets protection)
//
// Network tools:
//   - web_search: Search the web via SearXNG
//   - web_fetch: Fetch web pages (HTML, JSON, text) with SSRF protection
//
// Knowledge tools:
//   - knowledge_search: Search the knowledge base
//
// # Security
//
// All toolsets integrate security validators to prevent common vulnerabilities:
//   - Path validation prevents directory traversal attacks
//   - Command validation blocks dangerous shell commands (rm -rf, etc.)
//   - SSRF protection prevents access to private networks and cloud metadata
//   - Environment variable protection blocks access to secrets (API keys, tokens)
//
// # Usage Example
//
//	// Create toolsets with security validators
//	pathValidator, _ := security.NewPath([]string{"/allowed/path"})
//	fileToolset, err := tools.NewFileToolset(pathValidator, logger)
//	if err != nil {
//	    return err
//	}
//
//	cmdValidator := security.NewCommand()
//	envValidator := security.NewEnv()
//	systemToolset, err := tools.NewSystemToolset(cmdValidator, envValidator, logger)
//	if err != nil {
//	    return err
//	}
//
//	// Register toolsets with Chat agent
//	chatAgent, err := chat.New(chat.Deps{
//	    // ... other deps ...
//	    Toolsets: []tools.Toolset{fileToolset, systemToolset},
//	})
//
// # Tool Interface
//
// Tools implement the Tool interface and are wrapped in ExecutableTool for execution:
//
//	type Tool interface {
//	    Name() string
//	    Description() string
//	    IsLongRunning() bool
//	}
//
//	type ExecutableTool struct {
//	    // Contains tool metadata and execution function
//	}
//
// The Chat agent converts ExecutableTools to Genkit tools during initialization.
//
// # Error Handling
//
// Tool handlers return typed output structs. Errors are returned as Go errors:
//   - System errors (Go errors): Returned when tool execution fails
//   - Operational errors (in output): Included in output struct for LLM to handle
//
// # Extension
//
// To add a new toolset:
//
//  1. Define a struct implementing the Toolset interface
//  2. Create tool metadata types implementing the Tool interface
//  3. Implement handler functions with signature: func(*ai.ToolContext, InputType) (OutputType, error)
//  4. Return ExecutableTool instances from the Tools() method
//
// See the existing toolsets for complete examples.
package tools
