// Package chat provides Flow definition for Chat Agent
package chat

import (
	"context"
	"fmt"
	"sync"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"

	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/artifact"
)

// Input is the input for Chat Agent Flow
type Input struct {
	Query         string `json:"query"`
	SessionID     string `json:"sessionId"`     // Required field: session ID
	CanvasEnabled bool   `json:"canvasEnabled"` // When true, AI outputs interactive content (code, markdown) for Canvas panel
}

// Output is the output for Chat Agent Flow
type Output struct {
	Response  string `json:"response"`
	SessionID string `json:"sessionId"`
}

// StreamChunk is the streaming output type for Chat Flow.
// Each chunk contains partial text that can be immediately displayed to the user.
type StreamChunk struct {
	Text string `json:"text"` // Partial text chunk
	// TODO: Artifact extraction is not yet implemented.
	// This field is reserved for Canvas feature Phase 2 where AI-signaled artifacts
	// (code blocks, markdown, etc.) will be extracted from the stream and sent separately.
	// Until implemented, this field will always be nil.
	Artifact *artifact.Artifact `json:"artifact,omitempty"`
}

// FlowName is the registered name of the Chat Flow in Genkit.
const FlowName = "koopa/chat"

// Flow is the type alias for Chat Agent's Genkit Streaming Flow.
// Exported for use in api package with genkit.Handler().
type Flow = core.Flow[Input, Output, StreamChunk]

// Package-level singleton for Flow to prevent Panic on re-registration.
// sync.Once ensures the Flow is defined only once, even in tests.
var (
	flowOnce     sync.Once
	flow         *Flow
	flowInitDone bool
)

// InitFlow initializes the Chat Flow singleton.
// Must be called exactly once during application startup.
// Returns error if called more than once.
//
// This explicit API prevents the dangerous pattern where parameters
// are silently ignored on subsequent calls (as in the old GetFlow).
func InitFlow(g *genkit.Genkit, chatAgent *Chat) (*Flow, error) {
	var initialized bool
	flowOnce.Do(func() {
		flow = chatAgent.DefineFlow(g)
		flowInitDone = true
		initialized = true
	})
	if !initialized && flowInitDone {
		return nil, fmt.Errorf("InitFlow called more than once")
	}
	return flow, nil
}

// GetFlow returns the initialized Flow singleton.
// Panics if InitFlow was not called - this indicates a programming error.
func GetFlow() *Flow {
	if !flowInitDone {
		panic("GetFlow called before InitFlow")
	}
	return flow
}

// ResetFlowForTesting resets the Flow singleton for testing.
// This allows tests to initialize with different configurations.
// WARNING: Only use in tests. Not safe for concurrent use.
func ResetFlowForTesting() {
	flowOnce = sync.Once{}
	flow = nil
	flowInitDone = false
}

// DefineFlow defines the Genkit Streaming Flow for Chat Agent.
// Supports both streaming (via callback) and non-streaming modes.
//
// IMPORTANT: Use GetFlow() instead of calling DefineFlow() directly.
// DefineFlow registers a global Flow; calling it twice causes Panic.
//
// Each Agent has its own dedicated Flow, responsible for:
// 1. Observability (Genkit DevUI tracing)
// 2. Type safety (Input/Output schema)
// 3. HTTP endpoint exposure via genkit.Handler()
// 4. Streaming support for real-time output
//
// Design: Flow is a lightweight wrapper, Agent.ExecuteStream() contains core logic
//
// Error Handling :
// - Errors are now properly returned using sentinel errors from agent package
// - Genkit tracing will correctly show error spans
// - HTTP handlers can use errors.Is() to determine error type and HTTP status
//
//nolint:gocognit // Genkit Flow requires orchestration logic in single function
func (c *Chat) DefineFlow(g *genkit.Genkit) *Flow {
	return genkit.DefineStreamingFlow(g, FlowName,
		func(ctx context.Context, input Input, streamCb func(context.Context, StreamChunk) error) (Output, error) {
			// Parse session ID from input
			sessionID, err := uuid.Parse(input.SessionID)
			if err != nil {
				return Output{SessionID: input.SessionID}, fmt.Errorf("%w: %w", agent.ErrInvalidSession, err)
			}

			// Default branch for top-level agent
			branch := "main"

			// Create StreamCallback wrapper if streaming is enabled
			// When streamCb is nil (e.g., called via Run() instead of Stream()),
			// agentCallback will be nil and ExecuteStream will operate in non-streaming mode.
			var agentCallback StreamCallback
			if streamCb != nil {
				agentCallback = func(ctx context.Context, chunk *ai.ModelResponseChunk) error {
					// Extract text from chunk and stream it
					if chunk != nil && len(chunk.Content) > 0 {
						for _, part := range chunk.Content {
							if part.Text != "" {
								if streamErr := streamCb(ctx, StreamChunk{Text: part.Text}); streamErr != nil {
									return streamErr
								}
							}
						}
					}
					return nil
				}
			}

			// Execute with streaming callback (or non-streaming if callback is nil)
			// Pass canvasEnabled from Flow Input to instruct AI about Canvas mode
			resp, err := c.ExecuteStream(ctx, sessionID, branch, input.Query, input.CanvasEnabled, agentCallback)
			if err != nil {
				// Genkit will mark this span as failed, enabling proper observability
				return Output{SessionID: input.SessionID}, fmt.Errorf("%w: %w", agent.ErrExecutionFailed, err)
			}

			return Output{
				Response:  resp.FinalText,
				SessionID: input.SessionID,
			}, nil
		},
	)
}
