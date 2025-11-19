// Package tools provides Genkit tool registration and management.
//
// # Architecture
//
// This package implements the tool layer of the agent system, providing:
//   - Core tool registration (file, system, network operations)
//   - Centralized tool name registry (single source of truth)
//
// # Design Principles
//
//   - Dependency Injection: All validators passed as parameters
//   - No Package-Level State: Tools capture dependencies via closures
//   - Security First: All operations validated before execution
//
// # Tool Categories
//
//  1. File Tools (5): readFile, writeFile, listFiles, deleteFile, getFileInfo
//  2. System Tools (3): currentTime, executeCommand, getEnv
//  3. Network Tools (1): httpGet
//
// # Usage
//
// Tools are registered via RegisterTools() in agent initialization.
//
// Example:
//
//	tools.RegisterTools(g, pathVal, cmdVal, httpVal, envVal)
package tools

import (
	"fmt"

	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/security"
)

// toolNames contains all registered tool names
// This is the single source of truth for tool names to avoid duplication
var toolNames = []string{
	"currentTime",
	"readFile",
	"writeFile",
	"listFiles",
	"deleteFile",
	"executeCommand",
	"httpGet",
	"getEnv",
	"getFileInfo",
	"searchHistory",
	"searchDocuments",
	"searchSystemKnowledge",
}

// ToolNames returns all registered tool names
// This allows other packages to get the tool list without duplication
// Design: Go convention - no "Get" prefix for getters
func ToolNames() []string {
	return toolNames
}

// RegisterTools registers core tools with Genkit (file, system, network, knowledge)
// Validators are passed as parameters to create a Handler instance.
// This follows Go best practices (like http.Server, mcp.Server):
//   - Explicit dependencies via Handler struct
//   - Testable business logic in Handler methods
//   - Genkit closures as thin adapters for parameter conversion
//
// CRITICAL: knowledgeStore is required (cannot be nil).
// This function panics if knowledgeStore is nil, following Go's fail-fast pattern
// for critical dependencies (similar to http.Server panicking on nil Handler).
//
// Design: Accepts KnowledgeSearcher interface (not *knowledge.Store) following
// "Accept interfaces, return structs" principle for better testability.
func RegisterTools(
	g *genkit.Genkit,
	pathVal *security.Path,
	cmdVal *security.Command,
	httpVal *security.HTTP,
	envVal *security.Env,
	knowledgeStore KnowledgeSearcher,
) error {
	// CRITICAL: Fail-fast if knowledgeStore is nil
	// Knowledge tools are core P2 functionality and cannot work without the store.
	if knowledgeStore == nil {
		return fmt.Errorf("RegisterTools: knowledgeStore is required (cannot be nil)")
	}

	// Create handler with all validators (follows http.Server pattern)
	handler := NewHandler(pathVal, cmdVal, httpVal, envVal, knowledgeStore)

	// Register filesystem tools (5 tools)
	registerFileTools(g, handler)

	// Register system tools (3 tools)
	registerSystemTools(g, handler)

	// Register network tools (1 tool)
	registerNetworkTools(g, handler)

	// Register knowledge tools (3 tools)
	registerKnowledgeTools(g, handler)

	return nil
}
