// Package chat provides Flow definition for Chat Agent
package chat

import (
	"context"

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

// FlowName is the registered name of the Chat Flow in Genkit.
const FlowName = "koopa/chat"

// Flow is the type alias for Chat Agent's Genkit Flow.
// Exported for use in api package with genkit.Handler().
type Flow = core.Flow[Input, Output, struct{}]

// DefineFlow defines the Genkit Flow for Chat Agent and returns the Flow action.
// The returned action can be used with genkit.Handler() for HTTP exposure.
//
// Each Agent has its own dedicated Flow, responsible for:
// 1. Observability (Genkit DevUI tracing)
// 2. Type safety (Input/Output schema)
// 3. HTTP endpoint exposure via genkit.Handler()
//
// Design: Flow is a lightweight wrapper, Agent.Execute() contains core logic
func (a *Chat) DefineFlow(g *genkit.Genkit) *core.Flow[Input, Output, struct{}] {
	return genkit.DefineFlow(g, FlowName,
		func(ctx context.Context, input Input) (Output, error) {
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

			// Lightweight wrapper that delegates to Agent.Execute
			resp, err := a.Execute(invCtx, input.Query)
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
