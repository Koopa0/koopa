package agent

import (
	"fmt"

	"github.com/firebase/genkit/go/ai"
)

// InterruptEvent represents a tool execution that requires user confirmation.
type InterruptEvent struct {
	ToolName    string
	Parameters  map[string]any
	Reason      string
	DangerLevel DangerLevel

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
func buildToolResponse(interrupt *ai.Part, decision ConfirmationResponse) *ai.Part {
	toolName := interrupt.ToolRequest.Name // "requestConfirmation"

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

	return ai.NewToolResponsePart(&ai.ToolResponse{
		Name:   toolName,
		Output: output,
	})
}
