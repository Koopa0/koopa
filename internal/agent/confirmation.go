package agent

import (
	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// ConfirmationRequest is the input structure for the requestConfirmation tool.
type ConfirmationRequest struct {
	ToolToConfirm string         `json:"toolToConfirm"` // Tool name that needs confirmation
	Params        map[string]any `json:"params"`        // Tool parameters
	Reason        string         `json:"reason"`        // Why confirmation is needed (for user)
}

// RegisterConfirmationTool registers the requestConfirmation tool.
// This is the only tool LLM uses to request human confirmation.
func RegisterConfirmationTool(g *genkit.Genkit) {
	genkit.DefineTool(g, "requestConfirmation",
		"Before executing a dangerous operation, you must call this tool to request user approval.",
		func(ctx *ai.ToolContext, req ConfirmationRequest) (string, error) {
			// Note: metadata key names match InterruptEvent field names
			// so that helper functions can directly extract these fields
			return "", ctx.Interrupt(&ai.InterruptOptions{
				Metadata: map[string]any{
					"toolName":   req.ToolToConfirm,
					"parameters": req.Params,
					"reason":     req.Reason,
				},
			})
		},
	)
}
