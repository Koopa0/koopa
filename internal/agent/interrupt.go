package agent

import (
	"log/slog"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/tools"
)

// InterruptEvent represents a tool execution that requires user confirmation.
type InterruptEvent struct {
	ToolName    string
	Parameters  map[string]any
	Reason      string
	DangerLevel tools.DangerLevel

	IsRestartable bool   // Whether parameters can be modified and retried
	Question      string // If restartable, the question to ask the user

	// Raw Genkit interrupt object (for internal resume flow)
	rawInterrupt  *ai.Part // Exact type confirmed after P0 verification
	ResumeChannel chan<- ConfirmationResponse
}

// ConfirmationResponse is the user's decision on an interrupt.
type ConfirmationResponse struct {
	Approved       bool
	ModifiedParams map[string]any // Optional
	Reason         string         // Reason for rejection
}

// extractToolName extracts the tool name that needs confirmation from the interrupt.
// The interrupt.ToolRequest.Input contains the ConfirmationRequest in map form.
func extractToolName(interrupt *ai.Part) string {
	if interrupt.ToolRequest == nil {
		return ""
	}

	input, ok := interrupt.ToolRequest.Input.(map[string]any)
	if !ok {
		return ""
	}

	if toolName, ok := input["toolToConfirm"].(string); ok {
		return toolName
	}
	return ""
}

// extractParams extracts the tool parameters from the interrupt.
func extractParams(interrupt *ai.Part) map[string]any {
	if interrupt.ToolRequest == nil {
		return nil
	}

	input, ok := interrupt.ToolRequest.Input.(map[string]any)
	if !ok {
		return nil
	}

	if params, ok := input["params"].(map[string]any); ok {
		return params
	}
	return nil
}

// extractReason extracts the confirmation reason from the interrupt.
func extractReason(interrupt *ai.Part) string {
	if interrupt.ToolRequest == nil {
		return ""
	}

	input, ok := interrupt.ToolRequest.Input.(map[string]any)
	if !ok {
		return ""
	}

	if reason, ok := input["reason"].(string); ok {
		return reason
	}
	return ""
}

// buildToolResponse constructs a tool response to resume Genkit's execution flow.
// When the user approves/rejects, we need to tell Genkit the result.
//
// This function implements the same behavior as Genkit's tool.Respond():
// - Copies the Ref field from ToolRequest to ToolResponse for request/response correlation
// - Adds interruptResponse metadata to signal this is resuming an interrupt
func buildToolResponse(interrupt *ai.Part, decision ConfirmationResponse) *ai.Part {
	// Defensive nil checks with logging
	if interrupt == nil {
		slog.Warn("buildToolResponse called with nil interrupt")
		return nil
	}
	if interrupt.ToolRequest == nil {
		slog.Warn("buildToolResponse called with nil ToolRequest")
		return nil
	}

	toolName := interrupt.ToolRequest.Name // "requestConfirmation"
	toolRef := interrupt.ToolRequest.Ref   // Extract Ref for correlation

	var output any
	if decision.Approved {
		output = map[string]any{
			"status":  "approved",
			"message": "User approved this operation",
		}
	} else {
		output = map[string]any{
			"status":  "rejected",
			"message": fmt.Sprintf("User rejected: %s", decision.Reason),
		}
	}

	// Create tool response with Ref field copied
	resp := ai.NewToolResponsePart(&ai.ToolResponse{
		Name:   toolName,
		Ref:    toolRef, // Copy Ref for request/response correlation
		Output: output,
	})

	// Add Genkit-expected metadata (matches tool.Respond() behavior)
	resp.Metadata = map[string]any{
		"interruptResponse": true,
	}

	return resp
}
