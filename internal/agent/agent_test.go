package agent

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/config"
)

func createMockRetriever(g *genkit.Genkit) ai.Retriever {
	return genkit.DefineRetriever(
		g, "mock-retriever", nil,
		func(ctx context.Context, req *ai.RetrieverRequest) (*ai.RetrieverResponse, error) {
			return &ai.RetrieverResponse{
				Documents: []*ai.Document{},
			}, nil
		},
	)
}

func createTestAgent(t *testing.T) *Agent {
	t.Helper()

	// Set dummy API key for testing (required by config.Validate())
	os.Setenv("GEMINI_API_KEY", "test-api-key-for-unit-tests")
	t.Cleanup(func() {
		os.Unsetenv("GEMINI_API_KEY")
	})

	ctx := context.Background()
	// Initialize Genkit with prompts directory (needed to load system prompt)
	g := genkit.Init(ctx, genkit.WithPromptDir("../../prompts"))

	cfg := &config.Config{
		ModelName:      "gemini-2.0-flash-exp",
		Temperature:    0.7,
		MaxTokens:      2048,
		RAGTopK:        3,
		EmbedderModel:  "text-embedding-004",
		PostgresHost:   "localhost", // For testing, not actually connecting
		PostgresPort:   5432,
		PostgresDBName: "test_koopa",
	}

	retriever := createMockRetriever(g)

	agent, err := New(ctx, cfg, g, retriever)
	if err != nil {
		t.Fatalf("failed to create test agent: %v", err)
	}

	return agent
}

// TestAgentConcurrentHistoryAccess tests concurrent access to message history
func TestAgentConcurrentHistoryAccess(t *testing.T) {
	agent := createTestAgent(t)

	// Test concurrent reads and writes
	var wg sync.WaitGroup
	numGoroutines := 50
	numOperations := 100

	// Writers: add messages
	for i := range numGoroutines / 2 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for range numOperations {
				agent.messagesMu.Lock()
				agent.messages = append(agent.messages, ai.NewUserMessage(ai.NewTextPart("test")))
				agent.messagesMu.Unlock()
				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	// Readers: read history length
	for i := range numGoroutines / 2 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for range numOperations {
				_ = agent.HistoryLength()
				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	wg.Wait()

	// Verify final state
	finalLength := agent.HistoryLength()
	expectedLength := (numGoroutines / 2) * numOperations

	if finalLength != expectedLength {
		t.Errorf("expected history length %d, got %d", expectedLength, finalLength)
	}
}

// TestAgentClearHistory tests concurrent ClearHistory calls
func TestAgentClearHistory(t *testing.T) {
	agent := createTestAgent(t)

	// Add some messages
	for range 10 {
		agent.messagesMu.Lock()
		agent.messages = append(agent.messages, ai.NewUserMessage(ai.NewTextPart("test")))
		agent.messagesMu.Unlock()
	}

	if agent.HistoryLength() != 10 {
		t.Fatalf("expected 10 messages, got %d", agent.HistoryLength())
	}

	// Clear history
	agent.ClearHistory()

	if agent.HistoryLength() != 0 {
		t.Errorf("expected 0 messages after clear, got %d", agent.HistoryLength())
	}
}

// TestAgentConcurrentClearAndRead tests concurrent clear and read operations
func TestAgentConcurrentClearAndRead(t *testing.T) {
	agent := createTestAgent(t)

	var wg sync.WaitGroup
	numGoroutines := 20
	numIterations := 50

	// Add initial messages
	for range 100 {
		agent.messagesMu.Lock()
		agent.messages = append(agent.messages, ai.NewUserMessage(ai.NewTextPart("test")))
		agent.messagesMu.Unlock()
	}

	// Clearers
	for range numGoroutines / 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range numIterations {
				agent.ClearHistory()
				time.Sleep(time.Millisecond)
			}
		}()
	}

	// Readers
	for range numGoroutines * 3 / 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range numIterations {
				_ = agent.HistoryLength()
				time.Sleep(time.Microsecond)
			}
		}()
	}

	wg.Wait()

	// Should not panic or deadlock
	t.Log("concurrent clear and read completed successfully")
}

// TestConnectMCPConcurrency tests concurrent MCP connection attempts
func TestConnectMCPConcurrency(t *testing.T) {
	agent := createTestAgent(t)

	ctx := context.Background()
	var wg sync.WaitGroup
	numGoroutines := 10

	// Mock MCP configs (empty, will fail but that's ok for this test)
	configs := []struct{}{}

	// Try to connect concurrently
	for range numGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// This will fail because we don't have real MCP configs
			// but the important thing is sync.Once ensures only one attempt
			_ = agent.ConnectMCP(ctx, nil)
		}()
	}

	wg.Wait()

	// Verify sync.Once worked - mcpOnce should have been called exactly once
	// We can't directly verify this, but if there's a race condition,
	// the race detector will catch it
	t.Log("concurrent MCP connection attempts completed")

	// Verify configs is still the same (not used in test)
	_ = configs
}

// TestAgentHistoryTrimming tests the trimHistoryIfNeeded functionality
func TestAgentHistoryTrimming(t *testing.T) {
	// Set dummy API key for testing
	os.Setenv("GEMINI_API_KEY", "test-api-key-for-unit-tests")
	t.Cleanup(func() {
		os.Unsetenv("GEMINI_API_KEY")
	})

	ctx := context.Background()
	// Initialize Genkit with prompts directory
	g := genkit.Init(ctx, genkit.WithPromptDir("../../prompts"))

	cfg := &config.Config{
		ModelName:          "gemini-2.0-flash-exp",
		Temperature:        0.7,
		MaxTokens:          2048,
		RAGTopK:            3,
		EmbedderModel:      "text-embedding-004",
		PostgresHost:       "localhost", // For testing, not actually connecting
		PostgresPort:       5432,
		PostgresDBName:     "test_koopa",
		MaxHistoryMessages: 5, // Set small limit for testing
	}

	retriever := createMockRetriever(g)

	agent, err := New(ctx, cfg, g, retriever)
	if err != nil {
		t.Fatalf("failed to create test agent: %v", err)
	}

	// Add more messages than the limit
	for range 10 {
		agent.messagesMu.Lock()
		agent.messages = append(agent.messages, ai.NewUserMessage(ai.NewTextPart("test")))
		agent.trimHistoryIfNeeded()
		agent.messagesMu.Unlock()
	}

	// Should be trimmed to MaxHistoryMessages
	if agent.HistoryLength() != 5 {
		t.Errorf("expected history length 5 after trimming, got %d", agent.HistoryLength())
	}
}

// TestAgentHistoryUnlimited tests unlimited history (MaxHistoryMessages = 0)
func TestAgentHistoryUnlimited(t *testing.T) {
	// Set dummy API key for testing
	os.Setenv("GEMINI_API_KEY", "test-api-key-for-unit-tests")
	t.Cleanup(func() {
		os.Unsetenv("GEMINI_API_KEY")
	})

	ctx := context.Background()
	// Initialize Genkit with prompts directory
	g := genkit.Init(ctx, genkit.WithPromptDir("../../prompts"))

	cfg := &config.Config{
		ModelName:          "gemini-2.0-flash-exp",
		Temperature:        0.7,
		MaxTokens:          2048,
		RAGTopK:            3,
		EmbedderModel:      "text-embedding-004",
		PostgresHost:       "localhost", // For testing, not actually connecting
		PostgresPort:       5432,
		PostgresDBName:     "test_koopa",
		MaxHistoryMessages: 0, // Unlimited
	}

	retriever := createMockRetriever(g)

	agent, err := New(ctx, cfg, g, retriever)
	if err != nil {
		t.Fatalf("failed to create test agent: %v", err)
	}

	// Add many messages
	numMessages := 100
	for range numMessages {
		agent.messagesMu.Lock()
		agent.messages = append(agent.messages, ai.NewUserMessage(ai.NewTextPart("test")))
		agent.trimHistoryIfNeeded()
		agent.messagesMu.Unlock()
	}

	// Should keep all messages
	if agent.HistoryLength() != numMessages {
		t.Errorf("expected history length %d (unlimited), got %d", numMessages, agent.HistoryLength())
	}
}

// TestAgentMCPAccessor tests MCP() accessor method
func TestAgentMCPAccessor(t *testing.T) {
	agent := createTestAgent(t)

	// MCP should be nil before connection
	if agent.MCP() != nil {
		t.Error("expected nil MCP before connection")
	}

	// Try to connect (will fail with nil configs, but that's ok)
	ctx := context.Background()
	_ = agent.ConnectMCP(ctx, nil)

	// MCP accessor should still work (returns nil if connection failed)
	mcp := agent.MCP()
	_ = mcp // MCP is nil because we passed nil configs
}

// TestAgentCreationWithInvalidConfig tests Agent creation with invalid configurations
func TestAgentCreationWithInvalidConfig(t *testing.T) {
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPromptDir("../../prompts"))
	retriever := createMockRetriever(g)

	tests := []struct {
		name   string
		config *config.Config
		errMsg string
	}{
		{
			name: "nil genkit instance",
			config: &config.Config{
				ModelName:      "gemini-2.0-flash-exp",
				Temperature:    0.7,
				MaxTokens:      2048,
				RAGTopK:        3,
				EmbedderModel:  "text-embedding-004",
				PostgresHost:   "localhost",
				PostgresPort:   5432,
				PostgresDBName: "test",
			},
			errMsg: "genkit instance is required",
		},
		{
			name: "nil retriever",
			config: &config.Config{
				ModelName:      "gemini-2.0-flash-exp",
				Temperature:    0.7,
				MaxTokens:      2048,
				RAGTopK:        3,
				EmbedderModel:  "text-embedding-004",
				PostgresHost:   "localhost",
				PostgresPort:   5432,
				PostgresDBName: "test",
			},
			errMsg: "retriever is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var agent *Agent
			var err error

			if tt.name == "nil genkit instance" {
				agent, err = New(ctx, tt.config, nil, retriever)
			} else {
				agent, err = New(ctx, tt.config, g, nil)
			}

			if err == nil {
				t.Errorf("expected error containing %q, got nil", tt.errMsg)
			}
			if agent != nil {
				t.Error("expected nil agent on error")
			}
			if err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

// BenchmarkAgentConcurrentAccess benchmarks concurrent access patterns
func BenchmarkAgentConcurrentAccess(b *testing.B) {
	agent := createTestAgent(&testing.T{})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Mix of reads and writes
			if time.Now().UnixNano()%2 == 0 {
				agent.messagesMu.Lock()
				agent.messages = append(agent.messages, ai.NewUserMessage(ai.NewTextPart("test")))
				agent.messagesMu.Unlock()
			} else {
				_ = agent.HistoryLength()
			}
		}
	})
}

// ============================================================================
// Helper Function Tests
// ============================================================================

// TestTruncateString tests the truncateString helper function
func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "shorter than max",
			input:    "hello",
			maxLen:   10,
			expected: "hello",
		},
		{
			name:     "equal to max",
			input:    "helloworld",
			maxLen:   10,
			expected: "helloworld",
		},
		{
			name:     "longer than max",
			input:    "hello world this is a long string",
			maxLen:   10,
			expected: "hello worl...",
		},
		{
			name:     "empty string",
			input:    "",
			maxLen:   10,
			expected: "",
		},
		{
			name:     "unicode characters",
			input:    "HelloWorld!",
			maxLen:   6,
			expected: "HelloW...",
		},
		{
			name:     "max length zero",
			input:    "test",
			maxLen:   0,
			expected: "...",
		},
		{
			name:     "max length one",
			input:    "test",
			maxLen:   1,
			expected: "t...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("truncateString(%q, %d) = %q, want %q",
					tt.input, tt.maxLen, result, tt.expected)
			}
		})
	}
}

// TestAgentTools tests the tools() method
func TestAgentTools(t *testing.T) {
	agent := createTestAgent(t)
	ctx := context.Background()

	// Get tools without MCP
	tools := agent.tools(ctx)

	// Should have at least the core tools registered by tools.RegisterTools()
	// Core tools: readFile, writeFile, listFiles, deleteFile, getFileInfo,
	//             currentTime, executeCommand, getEnv, httpGet
	if len(tools) < 9 {
		t.Errorf("expected at least 9 core tools, got %d", len(tools))
	}

	// Verify tools are not nil
	for i, tool := range tools {
		if tool == nil {
			t.Errorf("tool at index %d is nil", i)
		}
	}
}

// TestPrepareGenerateOptions tests the prepareGenerateOptions method
func TestPrepareGenerateOptions(t *testing.T) {
	agent := createTestAgent(t)

	tests := []struct {
		name               string
		tools              []ai.ToolRef
		ragResp            *ai.RetrieverResponse
		ragErr             error
		userInput          string
		extraOpts          []ai.GenerateOption
		expectDocsIncluded bool
	}{
		{
			name:  "no RAG documents",
			tools: []ai.ToolRef{},
			ragResp: &ai.RetrieverResponse{
				Documents: []*ai.Document{},
			},
			ragErr:             nil,
			userInput:          "test query",
			extraOpts:          []ai.GenerateOption{},
			expectDocsIncluded: false,
		},
		{
			name:  "with RAG documents",
			tools: []ai.ToolRef{},
			ragResp: &ai.RetrieverResponse{
				Documents: []*ai.Document{
					{
						Content: []*ai.Part{ai.NewTextPart("doc1")},
					},
					{
						Content: []*ai.Part{ai.NewTextPart("doc2")},
					},
				},
			},
			ragErr:             nil,
			userInput:          "test query",
			extraOpts:          []ai.GenerateOption{},
			expectDocsIncluded: true,
		},
		{
			name:               "RAG error",
			tools:              []ai.ToolRef{},
			ragResp:            nil,
			ragErr:             context.DeadlineExceeded,
			userInput:          "test query",
			extraOpts:          []ai.GenerateOption{},
			expectDocsIncluded: false,
		},
		{
			name:               "nil RAG response",
			tools:              []ai.ToolRef{},
			ragResp:            nil,
			ragErr:             nil,
			userInput:          "test query",
			extraOpts:          []ai.GenerateOption{},
			expectDocsIncluded: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := agent.prepareGenerateOptions(
				tt.tools,
				tt.ragResp,
				tt.ragErr,
				tt.userInput,
				tt.extraOpts...,
			)

			// Verify we have at least base options (model, system, tools)
			if len(opts) < 3 {
				t.Errorf("expected at least 3 base options, got %d", len(opts))
			}

			// Note: We can't easily verify if WithDocs was included without
			// accessing private fields or running the actual generation.
			// This test mainly ensures the function doesn't panic and returns
			// a valid slice of options.
		})
	}
}
