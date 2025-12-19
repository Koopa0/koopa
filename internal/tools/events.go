package tools

import (
	"github.com/firebase/genkit/go/ai"
)

// WithEvents wraps a typed tool handler to emit lifecycle events.
// This generic version works directly with genkit.DefineTool().
//
// The wrapper:
//  1. Retrieves emitter from context (may be nil for non-streaming calls)
//  2. Emits OnToolStart before execution
//  3. Calls the original handler function
//  4. Emits OnToolComplete or OnToolError after execution
//
// If no emitter is in context, the wrapper simply passes through to the original function.
// This allows graceful degradation for non-streaming code paths.
func WithEvents[In, Out any](name string, fn func(*ai.ToolContext, In) (Out, error)) func(*ai.ToolContext, In) (Out, error) {
	return func(ctx *ai.ToolContext, input In) (Out, error) {
		// Retrieve emitter from context (may be nil for non-streaming calls)
		emitter := EmitterFromContext(ctx.Context)

		// Emit start event if emitter available
		if emitter != nil {
			emitter.OnToolStart(name)
		}

		// Execute original handler
		result, err := fn(ctx, input)

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
