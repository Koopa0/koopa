// Package chat provides Flow definition for Chat Agent
package chat

import (
	"context"
	"sync"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"

	"github.com/koopa0/koopa-cli/internal/agent"
)

// Input is the input for Chat Agent Flow
type Input struct {
	Query     string `json:"query"`
	SessionID string `json:"sessionId"` // Required field: session ID
}

// Output is the output for Chat Agent Flow
// Includes structured error handling
type Output struct {
	Response  string     `json:"response"`
	SessionID string     `json:"sessionId"`
	Error     *FlowError `json:"error,omitempty"` // Structured error
}

// FlowError is the structured error type for Flow
type FlowError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
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
// P0.5: Changed from non-streaming to streaming flow to support real-time output.
type Flow = core.Flow[Input, Output, StreamChunk]

// Package-level singleton for Flow to prevent Panic on re-registration.
// P0: DefineFlow registers a global Flow; calling it twice causes Panic.
// sync.Once ensures the Flow is defined only once, even in tests.
var (
	chatFlowOnce sync.Once
	chatFlow     *Flow // Must be package-level to persist across GetFlow() calls
)

// GetFlow returns the singleton Chat Flow instance.
// Uses sync.Once to ensure DefineFlow is called only once (preventing Panic).
// This function should be called during App initialization (Eager Loading)
// to ensure Genkit DevUI can discover the Flow at startup.
//
// IMPORTANT: This is a singleton access point. Parameters (g, chatAgent) are only
// used on the first call. Subsequent calls will return the cached Flow instance
// and ignore the provided parameters. This is intentional - the Flow must be
// registered exactly once with Genkit to avoid Panic.
func GetFlow(g *genkit.Genkit, chatAgent *Chat) *Flow {
	chatFlowOnce.Do(func() {
		chatFlow = chatAgent.DefineFlow(g)
	})
	return chatFlow
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
// 4. Streaming support for real-time output (P0.5)
//
// Design: Flow is a lightweight wrapper, Agent.ExecuteStream() contains core logic
func (a *Chat) DefineFlow(g *genkit.Genkit) *Flow {
	return genkit.DefineStreamingFlow(g, FlowName,
		func(ctx context.Context, input Input, streamCb func(context.Context, StreamChunk) error) (Output, error) {
			// Validate session ID from input
			sessionID, err := agent.NewSessionID(input.SessionID)
			if err != nil {
				return Output{
					SessionID: input.SessionID,
					Error: &FlowError{
						Code:    "INVALID_SESSION_ID",
						Message: err.Error(),
					},
				}, nil
			}

			// Generate InvocationID for tracking this call
			invocationID := uuid.New().String()

			// Create InvocationContext for execution tracking
			invCtx := agent.NewInvocationContext(
				ctx,
				invocationID,
				Name, // branch: top-level Agent
				sessionID,
				Name, // agentName
			)

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
								if err := streamCb(ctx, StreamChunk{Text: part.Text}); err != nil {
									return err
								}
							}
						}
					}
					return nil
				}
			}

			// Execute with streaming callback (or non-streaming if callback is nil)
			resp, err := a.ExecuteStream(invCtx, input.Query, agentCallback)
			if err != nil {
				// Structured error handling
				return Output{
					SessionID: input.SessionID,
					Error: &FlowError{
						Code:    "EXECUTION_FAILED",
						Message: err.Error(),
					},
				}, nil // Note: error is nil to allow Genkit to return 200
			}

			return Output{
				Response:  resp.FinalText,
				SessionID: input.SessionID,
			}, nil
		},
	)
}
