package agent

import (
	"context"
	"testing"

	"github.com/firebase/genkit/go/genkit"
)

// TestRegisterConfirmationTool verifies the tool is registered correctly.
// The actual tool execution logic (including validation and interrupt handling)
// is covered by existing Execute tests.
func TestRegisterConfirmationTool(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	// Register the confirmation tool
	RegisterConfirmationTool(g)

	// Verify the tool can be looked up
	tool := genkit.LookupTool(g, "requestConfirmation")
	if tool == nil {
		t.Fatal("requestConfirmation tool not found after registration")
	}

	// Tool successfully registered
	t.Log("requestConfirmation tool registered successfully")
}
