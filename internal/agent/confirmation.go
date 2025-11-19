package agent

import (
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// ConfirmationRequest is the input structure for the requestConfirmation tool.
// This struct is marshaled to JSON schema by Genkit for the LLM to understand.
type ConfirmationRequest struct {
	ToolToConfirm string         `json:"toolToConfirm" jsonschema_description:"Name of the tool that requires user confirmation (e.g., 'deleteFile', 'executeCommand')"`
	Params        map[string]any `json:"params" jsonschema_description:"The exact parameters that will be passed to the tool being confirmed. Must match the target tool's input schema."`
	Reason        string         `json:"reason" jsonschema_description:"Clear, human-readable explanation of what this operation will do and why it needs approval. Be specific about the action and its potential impact."`
}

// RegisterConfirmationTool registers the requestConfirmation tool.
// This is the only tool the LLM uses to request human-in-the-loop confirmation.
//
// Design: Tool triggers ctx.Interrupt() which returns toolInterruptError.
// Genkit detects this and sets FinishReasonInterrupted, allowing the agent's
// Execute() loop to handle user approval/rejection through InterruptEvent.
//
// Priority: P0 (Critical for safety)
func RegisterConfirmationTool(g *genkit.Genkit) {
	genkit.DefineTool(g, "requestConfirmation",
		"Request user confirmation before executing a potentially dangerous or destructive operation. "+
			"IMPORTANT: You MUST call this tool BEFORE calling any dangerous tool like deleteFile, executeCommand, "+
			"or any operation that modifies the system state irreversibly. "+
			"This tool will pause execution and ask the user for explicit approval. "+
			"Only proceed with the dangerous operation if the user approves. "+
			"If rejected, inform the user why the operation was cancelled and ask for alternative instructions. "+
			"\n\nUsage pattern:\n"+
			"1. Call requestConfirmation with the tool name, exact parameters, and clear reason\n"+
			"2. Wait for user decision (approval/rejection)\n"+
			"3. If approved: proceed with the original tool call\n"+
			"4. If rejected: acknowledge the rejection and ask what to do instead\n"+
			"\n"+
			"Example for file deletion:\n"+
			"Step 1: requestConfirmation(toolToConfirm='deleteFile', params={'path': '/important/data.txt'}, "+
			"reason='This will permanently delete /important/data.txt which contains user data.')\n"+
			"Step 2: If approved, call deleteFile(path='/important/data.txt')\n"+
			"Step 3: If rejected, inform user: 'Deletion cancelled. Would you like me to rename or backup the file instead?'",
		func(ctx *ai.ToolContext, req ConfirmationRequest) (string, error) {
			// Input validation (P2 quality improvement)
			if req.ToolToConfirm == "" {
				return "", fmt.Errorf("toolToConfirm is required and cannot be empty")
			}

			if req.Reason == "" {
				return "", fmt.Errorf("reason is required and cannot be empty - please explain what this operation will do")
			}

			// Trigger interrupt with forward-looking metadata
			// Note: toolToConfirm, params, and reason are automatically available in
			// ToolRequest.Input and extracted by helper functions (extractToolName, etc.)
			// We only add confirmationType for potential future UI differentiation.
			return "", ctx.Interrupt(&ai.InterruptOptions{
				Metadata: map[string]any{
					"confirmationType": "dangerous-operation",
				},
			})
		},
	)
}
