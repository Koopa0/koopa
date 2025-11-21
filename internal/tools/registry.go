// Package tools provides tool registration and management for the AI agent.
package tools

import (
	"context"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// Registry manages local tool lookup.
// It provides a unified interface for accessing locally registered tools.
//
// Design: Registry is stateless and thread-safe. It performs fresh lookups
// on each call to All(), ensuring tools are always up-to-date.
//
// Scope: Registry ONLY handles local tools. MCP tools are managed separately
// by the Agent to maintain clear separation of concerns.
//
// Thread Safety: Safe for concurrent use (no mutable state, pure lookup).
type Registry struct {
	g *genkit.Genkit
}

// NewRegistry creates a new tool registry.
//
// Parameters:
//   - g: Genkit instance for tool lookup (required, must not be nil)
//
// Returns:
//   - *Registry: Initialized registry ready to use
//
// Design: Simple constructor with minimal dependencies.
// Following stdlib patterns (e.g., http.NewServeMux()).
//
// Example:
//
//	registry := tools.NewRegistry(g)
//	allLocalTools := registry.All(ctx)
func NewRegistry(g *genkit.Genkit) *Registry {
	return &Registry{g: g}
}

// All returns all locally registered tools.
// Performs fresh lookup on each call to ensure tools are current.
//
// Returns:
//   - []ai.ToolRef: All available local tools
//
// Design:
//   - Fresh lookup: No caching ensures tools are always current
//   - Simple iteration: Uses ToolNames() as source of truth
//   - Non-blocking: Fast operation (local lookup only)
func (r *Registry) All(ctx context.Context) []ai.ToolRef {
	toolNames := ToolNames()
	toolRefs := make([]ai.ToolRef, 0, len(toolNames))

	for _, name := range toolNames {
		if tool := genkit.LookupTool(r.g, name); tool != nil {
			toolRefs = append(toolRefs, tool)
		}
	}

	return toolRefs
}

// Count returns the number of locally registered tools.
// Useful for monitoring and debugging.
//
// Returns:
//   - int: Number of local tools
//
// Design: Convenience method for observability.
func (r *Registry) Count(ctx context.Context) int {
	return len(r.All(ctx))
}
