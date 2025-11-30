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
	"github.com/koopa0/koopa-cli/internal/config"
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
//
// Note: Accepts testing.TB interface to support both *testing.T (tests) and
// *testing.B (benchmarks). This allows the same setup to be used in both contexts.
func SetupGoogleAI(tb testing.TB) *GoogleAISetup {
	tb.Helper()

	// Check for required API key
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		tb.Skip("GEMINI_API_KEY not set - skipping test requiring embedder")
	}

	ctx := context.Background()

	// Find project root to get absolute path to prompts directory
	projectRoot, err := findProjectRoot()
	if err != nil {
		tb.Fatalf("Failed to find project root: %v", err)
	}
	promptsDir := filepath.Join(projectRoot, "prompts")

	// Initialize Genkit with Google AI plugin
	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}),
		genkit.WithPromptDir(promptsDir))

	// Nil check: genkit.Init returns nil on internal initialization failure
	if g == nil {
		tb.Fatal("Failed to initialize Genkit: genkit.Init returned nil")
	}

	// Create embedder using config constant for maintainability
	embedder := googlegenai.GoogleAIEmbedder(g, config.DefaultEmbedderModel)

	// Nil check: GoogleAIEmbedder returns nil if model lookup fails
	if embedder == nil {
		tb.Fatalf("Failed to create embedder: GoogleAIEmbedder returned nil for model %q", config.DefaultEmbedderModel)
	}

	// Create quiet logger for tests (discard all logs)
	logger := slog.New(slog.DiscardHandler)

	return &GoogleAISetup{
		Embedder: embedder,
		Genkit:   g,
		Logger:   logger,
	}
}
