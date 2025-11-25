// Package chat provides Flow definition for Chat Agent
package chat

import (
	"context"

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

// DefineFlow defines the Genkit Flow for Chat Agent
// Each Agent has its own dedicated Flow, responsible for:
// 1. Observability (Genkit DevUI tracing)
// 2. Type safety (Input/Output schema)
// 3. HTTP endpoint exposure
//
// Design: Flow is a lightweight wrapper, Agent.Execute() contains core logic
func (a *Chat) DefineFlow(g *genkit.Genkit) {
	genkit.DefineFlow(g, "koopa/chat",
		func(ctx context.Context, input Input) (Output, error) {
			// Generate InvocationID for tracking this call
			invocationID := uuid.New().String()

			// Create InvocationContext for execution tracking
			invCtx := agent.NewInvocationContext(
				ctx,
				invocationID,
				Name, // branch: top-level Agent
				agent.NewSessionID(input.SessionID),
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
