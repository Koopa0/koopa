package testutil

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/koopa0/koopa/internal/config"
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

	setup, err := initGoogleAI()
	if err != nil {
		tb.Fatalf("initializing Google AI: %v", err)
	}
	return setup
}

// SetupGoogleAIForMain creates a Google AI embedder for use in TestMain.
//
// Unlike SetupGoogleAI, it returns an error instead of calling tb.Fatal.
// Returns nil and a descriptive error if GEMINI_API_KEY is not set.
//
// Example:
//
//	func TestMain(m *testing.M) {
//	    ai, err := testutil.SetupGoogleAIForMain()
//	    if err != nil {
//	        fmt.Println(err)
//	        os.Exit(0) // skip all tests
//	    }
//	    // use ai.Embedder, ai.Genkit, ai.Logger
//	}
func SetupGoogleAIForMain() (*GoogleAISetup, error) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		return nil, fmt.Errorf("GEMINI_API_KEY not set - skipping tests requiring embedder")
	}
	return initGoogleAI()
}

// initGoogleAI initializes Genkit with Google AI plugin and creates an embedder.
func initGoogleAI() (*GoogleAISetup, error) {
	ctx := context.Background()

	projectRoot, err := FindProjectRoot()
	if err != nil {
		return nil, fmt.Errorf("finding project root: %w", err)
	}
	promptsDir := filepath.Join(projectRoot, "prompts")

	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}),
		genkit.WithPromptDir(promptsDir))

	if g == nil {
		return nil, fmt.Errorf("genkit.Init returned nil")
	}

	embedder := googlegenai.GoogleAIEmbedder(g, config.DefaultGeminiEmbedderModel)
	if embedder == nil {
		return nil, fmt.Errorf("GoogleAIEmbedder returned nil for model %q", config.DefaultGeminiEmbedderModel)
	}

	return &GoogleAISetup{
		Embedder: embedder,
		Genkit:   g,
		Logger:   DiscardLogger(),
	}, nil
}
