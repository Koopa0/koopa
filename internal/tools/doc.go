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
//	    Definitions(ctx agent.ReadonlyContext, g *genkit.Genkit) ([]ToolDefinition, error)
//	}
//
// Each toolset encapsulates related functionality:
//   - FileToolset: File operations (read, write, list, delete)
//   - SystemToolset: System operations (time, commands, environment variables)
//   - NetworkToolset: Network operations (HTTP requests)
//   - KnowledgeToolset: Knowledge base operations (search, retrieval)
//
// # Security
//
// All toolsets integrate security validators to prevent common vulnerabilities:
//   - Path validation prevents directory traversal attacks
//   - Command validation blocks dangerous shell commands
//   - SSRF protection prevents access to private networks
//   - Environment variable protection blocks access to secrets
//
// # Usage Example
//
//	// Create toolsets with security validators
//	pathValidator := security.NewPath()
//	fileToolset, err := tools.NewFileToolset(pathValidator)
//	if err != nil {
//	    return err
//	}
//
//	cmdValidator := security.NewCommand()
//	envValidator := security.NewEnv()
//	systemToolset, err := tools.NewSystemToolset(cmdValidator, envValidator)
//	if err != nil {
//	    return err
//	}
//
//	// Register toolsets with an agent
//	agent, err := chat.New(
//	    chat.WithToolsets(fileToolset, systemToolset),
//	)
//
// # Tool Registration
//
// Tools are registered using the MakeDef function, which binds tool metadata
// to handler functions:
//
//	func (f *FileToolset) Definitions(ctx agent.ReadonlyContext, g *genkit.Genkit) ([]ToolDefinition, error) {
//	    return []ToolDefinition{
//	        MakeDef(g, &readFileTool{}, f.ReadFile),
//	        MakeDef(g, &writeFileTool{}, f.WriteFile),
//	    }, nil
//	}
//
// This pattern ensures type safety and separates tool metadata from implementation.
//
// # Error Handling
//
// Tool handlers return a Result type that encapsulates success/error states:
//
//	type Result struct {
//	    Status  ResultStatus       // StatusSuccess or StatusError
//	    Message string             // Human-readable message
//	    Data    map[string]any     // Result data (on success)
//	    Error   *Error             // Error details (on failure)
//	}
//
// This design allows tools to report both system errors (returned as Go errors)
// and operational errors (returned as Error in Result), enabling the LLM to
// make informed decisions about error recovery.
//
// # Extension
//
// To add a new toolset:
//
//  1. Define a struct implementing the Toolset interface
//  2. Create tool metadata types implementing the Tool interface
//  3. Implement handler functions with signature: func(*ai.ToolContext, InputType) (OutputType, error)
//  4. Register tools using MakeDef in the Definitions method
//
// See the existing toolsets for complete examples.
package tools
