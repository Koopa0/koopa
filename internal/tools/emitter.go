// Package tools provides tool abstractions for AI agent interactions.
package tools

import (
	"context"
)

// emitterKey uses empty struct for zero-allocation context key.
// Per Rob Pike: empty struct is idiomatic for context keys.
type emitterKey struct{}

// ToolEventEmitter receives tool lifecycle events.
// Interface is minimal - only tool name, no UI concerns.
// Per architecture-master: Interface for loose coupling between tools and SSE layer.
// UI presentation logic moved to web/handlers layer.
//
// Usage:
//  1. Handler creates emitter bound to SSE writer
//  2. Handler stores emitter in context via ContextWithEmitter()
//  3. Wrapped tool retrieves emitter via EmitterFromContext()
//  4. Tool calls OnToolStart/Complete/Error during execution
type ToolEventEmitter interface {
	// OnToolStart signals that a tool has started execution.
	// name: tool name (e.g., "web_search")
	// UI presentation (messages, icons) handled by web layer.
	OnToolStart(name string)

	// OnToolComplete signals that a tool completed successfully.
	// name: tool name
	OnToolComplete(name string)

	// OnToolError signals that a tool execution failed.
	// name: tool name
	// UI error messages handled by web layer.
	OnToolError(name string)
}

// EmitterFromContext retrieves ToolEventEmitter from context.
// Returns nil if not set, allowing graceful degradation (no events emitted).
// Per architecture-master: Non-streaming code paths won't have emitter set.
func EmitterFromContext(ctx context.Context) ToolEventEmitter {
	emitter, _ := ctx.Value(emitterKey{}).(ToolEventEmitter)
	return emitter
}

// ContextWithEmitter stores ToolEventEmitter in context.
// Per architecture-master: Per-request binding via context.Context.
func ContextWithEmitter(ctx context.Context, emitter ToolEventEmitter) context.Context {
	return context.WithValue(ctx, emitterKey{}, emitter)
}
