package flows

import (
	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
)

// DefineFlows defines all Genkit Flows
// This is the single entry point for registering all flows
//
// Parameters:
//   - g: Genkit instance
//   - modelRef: AI model reference with configuration
//   - systemPrompt: System prompt text for conversation flows
//   - pathVal: Path validator for security validation (dependency injection)
//
// Design principles:
//   - Flows are stateless - all state is passed in via input
//   - Each flow category is defined in its own file
//   - Shared utilities are in dedicated files (io.go)
//   - Validators are passed as parameters and captured by closures (Go best practice)
func DefineFlows(g *genkit.Genkit, modelRef ai.ModelRef, systemPrompt string, pathVal *security.PathValidator) {
	// Pass pathValidator as parameter, closures will capture it
	defineConversationFlows(g, modelRef, systemPrompt)
	defineAnalysisFlows(g, modelRef, pathVal)
	defineContentFlows(g, modelRef)
	defineDevelopmentFlows(g, modelRef, pathVal)
	defineProductivityFlows(g, modelRef)
}
