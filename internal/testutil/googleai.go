package testutil

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
)

// GoogleAISetup contains all resources needed for Google AI-based tests.
type GoogleAISetup struct {
	Embedder ai.Embedder
	Genkit   *genkit.Genkit
	Logger   *slog.Logger
}

// SetupGoogleAI creates a Google AI embedder with logger for testing.
//
// This is the preferred setup function for integration tests that need
// both embedder and logger with real Google AI API access.
//
// Requirements:
//   - GEMINI_API_KEY environment variable must be set
//   - Skips test if API key is not available
//
// Example:
//
//	func TestKnowledge(t *testing.T) {
//	    setup := testutil.SetupGoogleAI(t)
//	    store := knowledge.NewStore(pool, setup.Logger)
//	    // Use setup.Embedder, setup.Genkit, setup.Logger
//	}
func SetupGoogleAI(t *testing.T) *GoogleAISetup {
	t.Helper()

	// Check for required API key
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping test requiring embedder")
	}

	ctx := context.Background()

	// Find project root to get absolute path to prompts directory
	projectRoot, err := findProjectRoot()
	if err != nil {
		t.Fatalf("Failed to find project root: %v", err)
	}
	promptsDir := filepath.Join(projectRoot, "prompts")

	// Initialize Genkit with Google AI plugin
	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}),
		genkit.WithPromptDir(promptsDir))

	// Create embedder
	embedder := googlegenai.GoogleAIEmbedder(g, "text-embedding-004")

	// Create quiet logger for tests (discard all logs)
	logger := slog.New(slog.DiscardHandler)

	return &GoogleAISetup{
		Embedder: embedder,
		Genkit:   g,
		Logger:   logger,
	}
}
