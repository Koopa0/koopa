package testutil

import (
	"context"
	"os"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
)

// SetupEmbedder creates a Google AI embedder for testing.
//
// Requirements:
//   - GEMINI_API_KEY environment variable must be set
//   - Skips test if API key is not available
//
// Returns:
//   - ai.Embedder: Google AI embedder using text-embedding-004 model
//   - *genkit.Genkit: Genkit instance (needed for retriever creation)
//
// Example:
//
//	func TestEmbedding(t *testing.T) {
//	    embedder, g := testutil.SetupEmbedder(t)
//	    // Use embedder for embedding operations
//	}
func SetupEmbedder(t *testing.T) (ai.Embedder, *genkit.Genkit) {
	t.Helper()

	// Check for required API key
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping test requiring embedder")
	}

	ctx := context.Background()

	// Initialize Genkit with Google AI plugin
	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}),
		genkit.WithPromptDir("../../prompts"))

	// Create embedder
	embedder := googlegenai.GoogleAIEmbedder(g, "text-embedding-004")

	return embedder, g
}
