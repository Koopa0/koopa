package tools

import (
	"github.com/firebase/genkit/go/ai"
)

// WithEvents wraps a tool execution function to emit lifecycle events.
// Per genkit-master: Wrap the function BEFORE passing to genkit.DefineTool().
// Per architecture-master: Retrieve emitter from context for per-request binding.
//
// The wrapper:
//  1. Retrieves emitter from context (may be nil for non-streaming calls)
//  2. Emits OnToolStart before execution
//  3. Calls the original execution function
//  4. Emits OnToolComplete or OnToolError after execution
//
// If no emitter is in context, the wrapper simply passes through to the original function.
// This allows graceful degradation for non-streaming code paths.
func WithEvents(name string, execute func(ctx *ai.ToolContext, input any) (any, error)) func(ctx *ai.ToolContext, input any) (any, error) {
	return func(ctx *ai.ToolContext, input any) (any, error) {
		// Retrieve emitter from context (may be nil for non-streaming calls)
		// Per architecture-master: Graceful degradation when no emitter
		emitter := EmitterFromContext(ctx.Context)

		// Emit start event if emitter available
		if emitter != nil {
			emitter.OnToolStart(name)
		}

		// Execute original tool
		result, err := execute(ctx, input)

		// Emit complete/error event if emitter available
		if emitter != nil {
			if err != nil {
				emitter.OnToolError(name)
			} else {
				emitter.OnToolComplete(name)
			}
		}

		return result, err
	}
}
