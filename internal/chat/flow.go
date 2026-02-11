package chat

import (
	"context"
	"fmt"
	"sync"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
)

// Input defines the request payload for the chat agent flow.
type Input struct {
	Query     string `json:"query"`
	SessionID string `json:"sessionId"` // Required field: session ID
}

// Output defines the response payload from the chat agent flow.
type Output struct {
	Response  string `json:"response"`
	SessionID string `json:"sessionId"`
}

// StreamChunk is the streaming output type for Chat Flow.
// Each chunk contains partial text that can be immediately displayed to the user.
type StreamChunk struct {
	Text string `json:"text"` // Partial text chunk
}

// FlowName is the registered name of the Chat Flow in Genkit.
const FlowName = "koopa/chat"

// Flow is the type alias for Chat Agent's Genkit Streaming Flow.
// Exported for use in api package with genkit.Handler().
type Flow = core.Flow[Input, Output, StreamChunk]

// Package-level singleton for Flow to prevent panic on re-registration.
// sync.Once ensures genkit.DefineStreamingFlow is called only once.
var (
	flowOnce sync.Once
	flow     *Flow
)

// NewFlow returns the Chat Flow singleton, initializing it on first call.
// Subsequent calls return the existing Flow (parameters are ignored).
// This is safe because genkit.DefineStreamingFlow panics on re-registration.
func NewFlow(g *genkit.Genkit, agent *Agent) *Flow {
	flowOnce.Do(func() {
		flow = agent.DefineFlow(g)
	})
	return flow
}

// ResetFlowForTesting resets the Flow singleton for testing.
// This allows tests to initialize with different configurations.
// WARNING: Only use in tests. Not safe for concurrent use.
func ResetFlowForTesting() {
	flowOnce = sync.Once{}
	flow = nil
}

// DefineFlow defines the Genkit Streaming Flow for Chat Agent.
// Supports both streaming (via callback) and non-streaming modes.
//
// IMPORTANT: Use NewFlow() instead of calling DefineFlow() directly.
// DefineFlow registers a global Flow; calling it twice causes panic.
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
func (a *Agent) DefineFlow(g *genkit.Genkit) *Flow {
	return genkit.DefineStreamingFlow(g, FlowName,
		func(ctx context.Context, input Input, streamCb func(context.Context, StreamChunk) error) (Output, error) {
			// Parse session ID from input
			sessionID, err := uuid.Parse(input.SessionID)
			if err != nil {
				return Output{SessionID: input.SessionID}, fmt.Errorf("%w: %w", ErrInvalidSession, err)
			}

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
			resp, err := a.ExecuteStream(ctx, sessionID, input.Query, agentCallback)
			if err != nil {
				// Genkit will mark this span as failed, enabling proper observability
				return Output{SessionID: input.SessionID}, fmt.Errorf("%w: %w", ErrExecutionFailed, err)
			}

			return Output{
				Response:  resp.FinalText,
				SessionID: input.SessionID,
			}, nil
		},
	)
}
