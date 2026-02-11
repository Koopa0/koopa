package tools

import (
	"context"
)

// emitterKey is an unexported context key for zero-allocation type safety.
type emitterKey struct{}

// Emitter receives tool lifecycle events.
// Interface is minimal - only tool name, no UI concerns.
// UI presentation logic is handled by the SSE/API layer.
//
// Usage:
//  1. Handler creates emitter bound to SSE writer
//  2. Handler stores emitter in context via ContextWithEmitter()
//  3. Wrapped tool retrieves emitter via EmitterFromContext()
//  4. Tool calls OnToolStart/Complete/Error during execution
type Emitter interface {
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

// EmitterFromContext retrieves Emitter from context.
// Returns nil if not set, allowing graceful degradation (no events emitted).
func EmitterFromContext(ctx context.Context) Emitter {
	emitter, _ := ctx.Value(emitterKey{}).(Emitter)
	return emitter
}

// ContextWithEmitter stores Emitter in context for per-request binding.
func ContextWithEmitter(ctx context.Context, emitter Emitter) context.Context {
	return context.WithValue(ctx, emitterKey{}, emitter)
}
