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
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
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
}

// ToolNames returns all registered tool names
// This allows other packages to get the tool list without duplication
// Design: Go convention - no "Get" prefix for getters
func ToolNames() []string {
	return toolNames
}

// RegisterTools registers core tools with Genkit (file, system, network)
// Validators are passed as parameters and captured by closures (dependency injection pattern)
// This follows Go best practices: no package-level state, dependencies are explicit
func RegisterTools(
	g *genkit.Genkit,
	pathVal *security.PathValidator,
	cmdVal *security.CommandValidator,
	httpVal *security.HTTPValidator,
	envVal *security.EnvValidator,
) {
	// Register filesystem tools (5 tools)
	// Pass validators as parameters, closures will capture them
	registerFileTools(g, pathVal)

	// Register system tools (3 tools)
	registerSystemTools(g, cmdVal, envVal)

	// Register network tools (1 tool)
	registerNetworkTools(g, httpVal)
}
