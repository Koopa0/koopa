package tools

import (
	"encoding/json"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/agent"
)

// Toolset defines the interface for a collection of related tools.
// A toolset groups related tools together and provides them to the agent.
//
// Design principles:
// - Pure query method: Tools() has no side effects and is idempotent.
// - Context abstraction: Only uses ReadonlyContext (InvocationID, Branch, SessionID, AgentName).
// - Framework agnostic: Does not accept framework-specific parameters like *genkit.Genkit.
// - Separation of concerns: Business logic (Toolset) is independent from framework integration (Chat Agent).
type Toolset interface {
	// Name returns the unique identifier of the toolset.
	Name() string

	// Tools returns all tools provided by this toolset.
	// It is a pure query method with no side effects and can be called multiple times.
	// The returned tools are framework-agnostic and can be registered to any framework.
	Tools(ctx agent.ReadonlyContext) ([]Tool, error)
}

// Tool defines the interface for individual tools.
// Tools provide metadata about themselves but do not contain execution logic.
type Tool interface {
	// Name returns the unique identifier of the tool.
	Name() string

	// Description returns a description of the tool's functionality.
	// The LLM uses this to decide when to call the tool.
	Description() string

	// IsLongRunning indicates whether this tool performs long-running operations.
	// Long-running tools may need special handling (timeouts, progress tracking, etc.).
	IsLongRunning() bool
}

// ExecutableTool is a complete implementation of the Tool interface.
// It encapsulates both metadata and execution logic with type erasure
// to allow heterogeneous tool storage while maintaining compile-time type safety.
type ExecutableTool struct {
	name        string
	description string
	longRunning bool

	// handler is the type-erased execution function.
	// It accepts *ai.ToolContext (from Genkit) and any input/output.
	handler func(*ai.ToolContext, any) (any, error)
}

// Name returns the tool's unique identifier.
func (t *ExecutableTool) Name() string {
	return t.name
}

// Description returns the tool's functionality description.
func (t *ExecutableTool) Description() string {
	return t.description
}

// IsLongRunning returns whether the tool performs long-running operations.
func (t *ExecutableTool) IsLongRunning() bool {
	return t.longRunning
}

// Execute runs the tool with the given context and input.
func (t *ExecutableTool) Execute(ctx *ai.ToolContext, input any) (any, error) {
	return t.handler(ctx, input)
}

// NewTool creates a new tool with type-safe input and output handling.
//
// Type safety is guaranteed at compile time via generics [In, Out].
// Type erasure is performed internally to allow heterogeneous tool storage.
//
// Example:
//
//	readFileTool := NewTool(
//	    "readFile",
//	    "Read the complete content of any text-based file.",
//	    false,  // not long running
//	    func(ctx *ai.ToolContext, input ReadFileInput) (ReadFileOutput, error) {
//	        content, err := os.ReadFile(input.Path)
//	        if err != nil {
//	            return ReadFileOutput{}, err
//	        }
//	        return ReadFileOutput{Content: string(content), Path: input.Path}, nil
//	    },
//	)
func NewTool[In, Out any](
	name string,
	description string,
	longRunning bool,
	handler func(*ai.ToolContext, In) (Out, error),
) *ExecutableTool {
	var zeroIn In

	// Type adapter: converts generic handler to any-based handler.
	// This enables uniform storage of tools with different input/output types.
	// Supports both direct type assertion and JSON unmarshaling for Genkit compatibility.
	erasedHandler := func(ctx *ai.ToolContext, input any) (any, error) {
		// Try direct type assertion first
		if typedInput, ok := input.(In); ok {
			return handler(ctx, typedInput)
		}

		// Genkit passes map[string]any, need to convert via JSON
		jsonBytes, err := json.Marshal(input)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal input: %w", err)
		}

		var typedInput In
		if err := json.Unmarshal(jsonBytes, &typedInput); err != nil {
			return nil, fmt.Errorf("invalid input type: expected %T, got %T (unmarshal error: %w)", zeroIn, input, err)
		}
		return handler(ctx, typedInput)
	}

	return &ExecutableTool{
		name:        name,
		description: description,
		longRunning: longRunning,
		handler:     erasedHandler,
	}
}
