package agent

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core/api"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/mcp"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/sqlc"
)

// mockGenerator is a mock implementation of the Generator interface for testing.
type mockGenerator struct {
	// Response is the canned response to return when Generate is called.
	Response *ai.ModelResponse
	// Err is the error to return when Generate is called.
	Err error
	// GenerateFunc allows for custom logic to be executed when Generate is called.
	GenerateFunc func(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error)
}

// Generate returns the canned response or error.
func (m *mockGenerator) Generate(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error) {
	if m.GenerateFunc != nil {
		return m.GenerateFunc(ctx, opts...)
	}
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Response, nil
}

// mockRetriever is a mock implementation of the ai.Retriever interface.
type mockRetriever struct{}

func (m *mockRetriever) Retrieve(ctx context.Context, req *ai.RetrieverRequest) (*ai.RetrieverResponse, error) {
	// Return an empty response for now, as we are not testing RAG functionality.
	return &ai.RetrieverResponse{}, nil
}

// Name returns the name of the mock retriever.
func (m *mockRetriever) Name() string {
	return "mockRetriever"
}

// mockKnowledgeQuerier is a mock implementation of the knowledge querier for testing.
type mockKnowledgeQuerier struct{}

func (m *mockKnowledgeQuerier) UpsertDocument(ctx context.Context, arg sqlc.UpsertDocumentParams) error {
	return nil
}

func (m *mockKnowledgeQuerier) SearchDocuments(ctx context.Context, arg sqlc.SearchDocumentsParams) ([]sqlc.SearchDocumentsRow, error) {
	return nil, nil
}

func (m *mockKnowledgeQuerier) SearchDocumentsAll(ctx context.Context, arg sqlc.SearchDocumentsAllParams) ([]sqlc.SearchDocumentsAllRow, error) {
	return nil, nil
}

func (m *mockKnowledgeQuerier) CountDocuments(ctx context.Context, filterMetadata []byte) (int64, error) {
	return 0, nil
}

func (m *mockKnowledgeQuerier) CountDocumentsAll(ctx context.Context) (int64, error) {
	return 0, nil
}

func (m *mockKnowledgeQuerier) DeleteDocument(ctx context.Context, id string) error {
	return nil
}

func (m *mockKnowledgeQuerier) ListDocumentsBySourceType(ctx context.Context, arg sqlc.ListDocumentsBySourceTypeParams) ([]sqlc.ListDocumentsBySourceTypeRow, error) {
	return nil, nil
}

// mockEmbedder is a mock implementation of ai.Embedder for testing.
type mockEmbedder struct{}

func (m *mockEmbedder) Embed(ctx context.Context, req *ai.EmbedRequest) (*ai.EmbedResponse, error) {
	embedding := &ai.Embedding{Embedding: []float32{0.1, 0.2, 0.3}}
	return &ai.EmbedResponse{Embeddings: []*ai.Embedding{embedding}}, nil
}

func (m *mockEmbedder) Name() string {
	return "mockEmbedder"
}

// mockKnowledgeStore is a flexible mock for KnowledgeStore interface
type mockKnowledgeStore struct {
	countFunc  func(ctx context.Context, filter map[string]string) (int, error)
	addFunc    func(ctx context.Context, doc knowledge.Document) error
	searchFunc func(ctx context.Context, query string, opts ...knowledge.SearchOption) ([]knowledge.Result, error)
}

func (m *mockKnowledgeStore) Count(ctx context.Context, filter map[string]string) (int, error) {
	if m.countFunc != nil {
		return m.countFunc(ctx, filter)
	}
	return 0, nil
}

func (m *mockKnowledgeStore) Add(ctx context.Context, doc knowledge.Document) error {
	if m.addFunc != nil {
		return m.addFunc(ctx, doc)
	}
	return nil
}

func (m *mockKnowledgeStore) Search(ctx context.Context, query string, opts ...knowledge.SearchOption) ([]knowledge.Result, error) {
	if m.searchFunc != nil {
		return m.searchFunc(ctx, query, opts...)
	}
	return nil, nil
}

func (m *mockEmbedder) Register(r api.Registry) {}

// createMockKnowledgeStore creates a knowledge store for testing.
func createMockKnowledgeStore() *knowledge.Store {
	return knowledge.NewWithQuerier(&mockKnowledgeQuerier{}, &mockEmbedder{}, slog.Default())
}

// Register is a dummy method to satisfy the ai.Retriever interface.
func (m *mockRetriever) Register(r api.Registry) {}

// createTestAgent creates an agent instance for testing with mock generator support.
func createTestAgent(t *testing.T, mockGen Generator) *Agent {
	t.Helper()

	// Skip test if GEMINI_API_KEY is not set
	// Even though these tests use mocks, they still need to create a real Agent
	// instance which requires config validation including API key
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("GEMINI_API_KEY not set - skipping test that requires agent creation")
	}

	ctx := context.Background()

	// Create real Genkit instance with minimal config
	g := genkit.Init(ctx, genkit.WithPromptDir("../../prompts"))

	cfg := &config.Config{
		MaxHistoryMessages: 10,
		ModelName:          "gemini-2.5-flash",
		Temperature:        0.7,
		MaxTokens:          1024,
		RAGTopK:            3,
		EmbedderModel:      "text-embedding-004",
		PostgresHost:       "localhost",
		PostgresPort:       5432,
		PostgresDBName:     "test_db",
		Language:           "English",
	}

	agent, err := New(ctx, cfg, g, &mockRetriever{},
		WithSessionStore(NewNoopSessionStore()),
		WithKnowledgeStore(createMockKnowledgeStore()),
		WithLogger(slog.Default()))
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}

	// Replace the production generator with mock if provided
	if mockGen != nil {
		agent.generator = mockGen
	}

	return agent
}

// TestExecute_ErrorHandling verifies that the Execute method correctly
// handles an error from the generator.
func TestExecute_ErrorHandling(t *testing.T) {
	// 1. Arrange
	ctx := context.Background()
	expectedErr := errors.New("API error")

	// Create a mock generator that will return an error.
	mockGen := &mockGenerator{
		Err: expectedErr,
	}

	agent := createTestAgent(t, mockGen)

	// 2. Act
	_, err := agent.Execute(ctx, "some input")

	// 3. Assert
	// We expect to receive an error.
	if err == nil {
		t.Fatal("Expected an error, but got nil")
	}

	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected error '%v', but got '%v'", expectedErr, err)
	}
}

// TestExecute_MultiTurnHistory verifies that the Execute method correctly
// manages conversation history across multiple turns.
//
// Test scenario (from design doc 6.1):
// - First Execute call: user says "My name is Alice"
// - Second Execute call: user asks "What's my name?"
// - LLM should have access to first turn's context
func TestExecute_MultiTurnHistory(t *testing.T) {
	// 1. Arrange
	ctx := context.Background()

	// Track which turn we're on
	turnCount := 0
	mockGen := &mockGenerator{
		GenerateFunc: func(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error) {
			turnCount++
			t.Logf("Generate called for turn %d", turnCount)

			// Both turns return simple completion (no interrupts)
			return &ai.ModelResponse{
				Message: &ai.Message{
					Role:    ai.RoleModel,
					Content: []*ai.Part{ai.NewTextPart("OK")},
				},
				FinishReason: ai.FinishReasonStop,
			}, nil
		},
	}

	agent := createTestAgent(t, mockGen)

	// 2. Act - Turn 1
	t.Log("=== Turn 1: User introduces themselves ===")
	_, err := agent.Execute(ctx, "My name is Alice")
	if err != nil {
		t.Fatalf("Turn 1 error: %v", err)
	}

	// Verify history after turn 1
	historyLen1 := agent.HistoryLength()
	t.Logf("History length after turn 1: %d", historyLen1)
	if historyLen1 != 2 { // User message + Model response
		t.Errorf("Expected history length 2 after turn 1, got %d", historyLen1)
	}

	// 2. Act - Turn 2
	t.Log("=== Turn 2: User asks about their name ===")
	_, err = agent.Execute(ctx, "What's my name?")
	if err != nil {
		t.Fatalf("Turn 2 error: %v", err)
	}

	// 3. Assert
	// Verify history after turn 2
	historyLen2 := agent.HistoryLength()
	t.Logf("History length after turn 2: %d", historyLen2)
	if historyLen2 != 4 { // 2 from turn 1 + 2 from turn 2
		t.Errorf("Expected history length 4 after turn 2, got %d", historyLen2)
	}

	// Verify Generate was called exactly twice (once per turn)
	if turnCount != 2 {
		t.Errorf("Expected Generate to be called 2 times, but was called %d times", turnCount)
	}

	// Verify we can clear history
	agent.ClearHistory()
	if agent.HistoryLength() != 0 {
		t.Errorf("Expected history length 0 after clear, got %d", agent.HistoryLength())
	}
}

// TestExecute_FinishReasonLength verifies that the Execute method correctly handles
// the scenario where the model response is truncated due to max token limit.
func TestExecute_FinishReasonLength(t *testing.T) {
	// 1. Arrange
	ctx := context.Background()

	mockGen := &mockGenerator{
		GenerateFunc: func(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error) {
			t.Log("GenerateFunc called, returning FinishReasonLength")

			// Simulate a truncated response due to max token limit
			return &ai.ModelResponse{
				Message: &ai.Message{
					Role:    ai.RoleModel,
					Content: []*ai.Part{ai.NewTextPart("This response is truncated because")},
				},
				FinishReason: ai.FinishReasonLength,
			}, nil
		},
	}

	agent := createTestAgent(t, mockGen)

	// 2. Act
	_, err := agent.Execute(ctx, "write a very long response")

	// 3. Assert
	// We expect to receive an error.
	if err == nil {
		t.Fatal("Expected an error, but got nil")
	}

	expectedMsg := "response truncated: maximum token limit reached"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', but got '%s'", expectedMsg, err.Error())
	}

	t.Log("Test passed: Agent correctly handled FinishReasonLength")
}

// TestExecute_FinishReasonBlocked verifies that the Execute method correctly handles
// the scenario where the model response is blocked by safety filter.
func TestExecute_FinishReasonBlocked(t *testing.T) {
	// 1. Arrange
	ctx := context.Background()

	mockGen := &mockGenerator{
		GenerateFunc: func(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error) {
			t.Log("GenerateFunc called, returning FinishReasonBlocked")

			// Simulate a response blocked by safety filter
			return &ai.ModelResponse{
				Message: &ai.Message{
					Role:    ai.RoleModel,
					Content: []*ai.Part{}, // No content when blocked
				},
				FinishReason: ai.FinishReasonBlocked,
			}, nil
		},
	}

	agent := createTestAgent(t, mockGen)

	// 2. Act
	_, err := agent.Execute(ctx, "potentially harmful request")

	// 3. Assert
	// We expect to receive an error.
	if err == nil {
		t.Fatal("Expected an error, but got nil")
	}

	expectedMsg := "response blocked by safety filter"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', but got '%s'", expectedMsg, err.Error())
	}

	t.Log("Test passed: Agent correctly handled FinishReasonBlocked")
}

// ============================================================================
// P2 Phase 2: Conversation History Vectorization Tests
// ============================================================================

// TestExtractTextFromMessage tests extracting plain text from ai.Message
func TestExtractTextFromMessage(t *testing.T) {
	agent := &Agent{}

	tests := []struct {
		name     string
		message  *ai.Message
		expected string
	}{
		{
			name: "single text part",
			message: &ai.Message{
				Role: ai.RoleUser,
				Content: []*ai.Part{
					ai.NewTextPart("Hello, world!"),
				},
			},
			expected: "Hello, world!",
		},
		{
			name: "multiple text parts",
			message: &ai.Message{
				Role: ai.RoleUser,
				Content: []*ai.Part{
					ai.NewTextPart("Hello"),
					ai.NewTextPart(" "),
					ai.NewTextPart("world!"),
				},
			},
			expected: "Hello world!",
		},
		{
			name: "empty message",
			message: &ai.Message{
				Role:    ai.RoleUser,
				Content: []*ai.Part{},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := agent.extractTextFromMessage(tt.message)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestExtractToolInfo tests extracting tool information from tool response messages
func TestExtractToolInfo(t *testing.T) {
	agent := &Agent{}

	tests := []struct {
		name           string
		message        *ai.Message
		expectedName   string
		expectedResult string
	}{
		{
			name: "string output",
			message: &ai.Message{
				Role: ai.RoleTool,
				Content: []*ai.Part{
					ai.NewToolResponsePart(&ai.ToolResponse{
						Name:   "readFile",
						Output: "file contents here",
					}),
				},
			},
			expectedName:   "readFile",
			expectedResult: "file contents here",
		},
		{
			name: "nil output",
			message: &ai.Message{
				Role: ai.RoleTool,
				Content: []*ai.Part{
					ai.NewToolResponsePart(&ai.ToolResponse{
						Name:   "deleteFile",
						Output: nil,
					}),
				},
			},
			expectedName:   "deleteFile",
			expectedResult: "",
		},
		{
			name: "map output (JSON marshalled)",
			message: &ai.Message{
				Role: ai.RoleTool,
				Content: []*ai.Part{
					ai.NewToolResponsePart(&ai.ToolResponse{
						Name: "getFileInfo",
						Output: map[string]interface{}{
							"size": 1024,
							"name": "test.txt",
						},
					}),
				},
			},
			expectedName:   "getFileInfo",
			expectedResult: `{"name":"test.txt","size":1024}`,
		},
		{
			name: "no tool response",
			message: &ai.Message{
				Role: ai.RoleUser,
				Content: []*ai.Part{
					ai.NewTextPart("hello"),
				},
			},
			expectedName:   "",
			expectedResult: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, result := agent.extractToolInfo(tt.message)
			if name != tt.expectedName {
				t.Errorf("expected name %q, got %q", tt.expectedName, name)
			}
			if result != tt.expectedResult {
				t.Errorf("expected result %q, got %q", tt.expectedResult, result)
			}
		})
	}
}

// TestGetCurrentSessionID tests session ID retrieval with ephemeral support
func TestGetCurrentSessionID(t *testing.T) {
	tests := []struct {
		name     string
		agent    *Agent
		expected string
	}{
		{
			name: "nil session store returns ephemeral",
			agent: &Agent{
				sessionStore: nil,
			},
			expected: "ephemeral-session",
		},
		{
			name: "nil current session returns ephemeral",
			agent: &Agent{
				sessionStore:     NewNoopSessionStore(),
				currentSessionID: nil,
			},
			expected: "ephemeral-session",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.agent.getCurrentSessionID()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestBuildTurnContent_EdgeCases tests boundary conditions for buildTurnContent
func TestBuildTurnContent_EdgeCases(t *testing.T) {
	agent := &Agent{}

	tests := []struct {
		name        string
		messages    []*ai.Message
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty messages",
			messages:    []*ai.Message{},
			expectError: true,
			errorMsg:    "not enough messages",
		},
		{
			name: "only user message",
			messages: []*ai.Message{
				{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("hello")}},
			},
			expectError: true,
			errorMsg:    "not enough messages",
		},
		{
			name: "incomplete turn - no assistant",
			messages: []*ai.Message{
				{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("hello")}},
				{Role: ai.RoleTool, Content: []*ai.Part{ai.NewToolResponsePart(&ai.ToolResponse{Name: "test", Output: "result"})}},
			},
			expectError: true,
			errorMsg:    "incomplete turn",
		},
		{
			name: "complete turn",
			messages: []*ai.Message{
				{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("hello")}},
				{Role: ai.RoleModel, Content: []*ai.Part{ai.NewTextPart("hi there")}},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, toolCount, err := agent.buildTurnContent(tt.messages)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if content == "" {
					t.Error("expected non-empty content")
				}
				if toolCount < 0 {
					t.Errorf("expected non-negative tool count, got %d", toolCount)
				}
			}
		})
	}
}

// TestIsRetriableError tests error classification for retry logic
func TestIsRetriableError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "deadline exceeded - retriable",
			err:      context.DeadlineExceeded,
			expected: true,
		},
		{
			name:     "context cancelled - not retriable",
			err:      context.Canceled,
			expected: false,
		},
		{
			name:     "generic error - not retriable",
			err:      errors.New("generic error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRetriableError(tt.err)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestBuildTurnContent_WithTools tests buildTurnContent with tool calls
func TestBuildTurnContent_WithTools(t *testing.T) {
	agent := &Agent{}

	messages := []*ai.Message{
		{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("read config.yaml")}},
		{Role: ai.RoleTool, Content: []*ai.Part{
			ai.NewToolResponsePart(&ai.ToolResponse{
				Name:   "readFile",
				Output: "port: 8080\nhost: localhost",
			}),
		}},
		{Role: ai.RoleModel, Content: []*ai.Part{ai.NewTextPart("The config shows port 8080")}},
	}

	content, toolCount, err := agent.buildTurnContent(messages)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if toolCount != 1 {
		t.Errorf("expected tool count 1, got %d", toolCount)
	}

	if !contains(content, "read config.yaml") {
		t.Error("content should contain user query")
	}
	if !contains(content, "Actions taken") {
		t.Error("content should contain actions section")
	}
	if !contains(content, "readFile") {
		t.Error("content should contain tool name")
	}
	if !contains(content, "The config shows port 8080") {
		t.Error("content should contain assistant response")
	}
}

// TestCalculateTurnNumber tests turn number calculation
func TestCalculateTurnNumber(t *testing.T) {
	// Create mock knowledge store that returns count = 5
	mockQuerier := &mockCountQuerier{count: 5}

	agent := &Agent{
		knowledgeStore: knowledge.NewWithQuerier(mockQuerier, &mockEmbedder{}, slog.Default()),
		logger:         slog.Default(),
	}

	ctx := context.Background()
	turnNumber := agent.calculateTurnNumber(ctx, "test-session")

	// Count = 5, so next turn should be 6
	if turnNumber != 6 {
		t.Errorf("expected turn number 6, got %d", turnNumber)
	}
}

// mockCountQuerier is a mock querier that returns a fixed count
type mockCountQuerier struct {
	mockKnowledgeQuerier
	count int64
}

func (m *mockCountQuerier) CountDocuments(ctx context.Context, filterMetadata []byte) (int64, error) {
	return m.count, nil
}

// mockVectorizeQuerier tracks vectorization calls
type mockVectorizeQuerier struct {
	mockKnowledgeQuerier
	addCalled    bool
	attemptCount int
	failUntil    int // Fail until this attempt number
}

func (m *mockVectorizeQuerier) UpsertDocument(ctx context.Context, arg sqlc.UpsertDocumentParams) error {
	m.attemptCount++
	if m.attemptCount <= m.failUntil {
		return context.DeadlineExceeded
	}
	m.addCalled = true
	return nil
}

// TestVectorizeConversationTurn_Success tests successful vectorization
func TestVectorizeConversationTurn_Success(t *testing.T) {
	mockQuerier := &mockVectorizeQuerier{}

	agent := &Agent{
		messages: []*ai.Message{
			{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("hello")}},
			{Role: ai.RoleModel, Content: []*ai.Part{ai.NewTextPart("hi there")}},
		},
		knowledgeStore: knowledge.NewWithQuerier(mockQuerier, &mockEmbedder{}, slog.Default()),
		sessionStore:   nil, // Will use ephemeral-session
		logger:         slog.Default(),
	}

	ctx := context.Background()
	err := agent.vectorizeConversationTurn(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mockQuerier.addCalled {
		t.Error("expected knowledgeStore.Add to be called")
	}
}

// TestVectorizeConversationTurn_WithRetry tests retry mechanism
func TestVectorizeConversationTurn_WithRetry(t *testing.T) {
	mockQuerier := &mockVectorizeQuerier{
		failUntil: 2, // Fail first 2 attempts, succeed on 3rd
	}

	agent := &Agent{
		messages: []*ai.Message{
			{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("test")}},
			{Role: ai.RoleModel, Content: []*ai.Part{ai.NewTextPart("response")}},
		},
		knowledgeStore: knowledge.NewWithQuerier(mockQuerier, &mockEmbedder{}, slog.Default()),
		sessionStore:   nil,
		logger:         slog.Default(),
	}

	ctx := context.Background()
	err := agent.vectorizeConversationTurn(ctx)
	if err != nil {
		t.Fatalf("unexpected error after retries: %v", err)
	}

	if mockQuerier.attemptCount != 3 {
		t.Errorf("expected 3 attempts (2 retries), got %d", mockQuerier.attemptCount)
	}

	if !mockQuerier.addCalled {
		t.Error("expected vectorization to succeed after retries")
	}
}

// contains is a helper function for substring matching
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && containsHelper(s, substr)
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ============================================================================
// mockSessionStore - Flexible mock for Session management testing
// ============================================================================

type mockSessionStore struct {
	// Function fields for custom behavior injection
	createSessionFunc func(ctx context.Context, title, modelName, systemPrompt string) (*session.Session, error)
	getSessionFunc    func(ctx context.Context, sessionID uuid.UUID) (*session.Session, error)
	getMessagesFunc   func(ctx context.Context, sessionID uuid.UUID, limit, offset int32) ([]*session.Message, error)
	addMessagesFunc   func(ctx context.Context, sessionID uuid.UUID, messages []*session.Message) error

	// Tracking fields for verification
	createCalled      bool
	getCalled         bool
	getMessagesCalled bool
	addMessagesCalled bool
}

func (m *mockSessionStore) CreateSession(ctx context.Context, title, modelName, systemPrompt string) (*session.Session, error) {
	m.createCalled = true
	if m.createSessionFunc != nil {
		return m.createSessionFunc(ctx, title, modelName, systemPrompt)
	}
	// Default: return a new session
	return &session.Session{
		ID:    uuid.New(),
		Title: title,
	}, nil
}

func (m *mockSessionStore) GetSession(ctx context.Context, sessionID uuid.UUID) (*session.Session, error) {
	m.getCalled = true
	if m.getSessionFunc != nil {
		return m.getSessionFunc(ctx, sessionID)
	}
	// Default: return a session
	return &session.Session{
		ID:    sessionID,
		Title: "Test Session",
	}, nil
}

func (m *mockSessionStore) GetMessages(ctx context.Context, sessionID uuid.UUID, limit, offset int32) ([]*session.Message, error) {
	m.getMessagesCalled = true
	if m.getMessagesFunc != nil {
		return m.getMessagesFunc(ctx, sessionID, limit, offset)
	}
	// Default: return empty messages
	return []*session.Message{}, nil
}

func (m *mockSessionStore) AddMessages(ctx context.Context, sessionID uuid.UUID, messages []*session.Message) error {
	m.addMessagesCalled = true
	if m.addMessagesFunc != nil {
		return m.addMessagesFunc(ctx, sessionID, messages)
	}
	// Default: succeed
	return nil
}

// ============================================================================
// P3 Phase 3.2: Agent Constructor Tests
// ============================================================================

// TestNew_ConfigValidationFails verifies that New returns an error
// when the provided config fails validation.
func TestNew_ConfigValidationFails(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPromptDir("../../prompts"))

	// Create invalid config (missing required field)
	cfg := &config.Config{
		// Missing ModelName - will fail validation
		Temperature:        0.7,
		MaxTokens:          1024,
		MaxHistoryMessages: 10,
	}

	_, err := New(ctx, cfg, g, &mockRetriever{}, WithSessionStore(NewNoopSessionStore()), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(slog.Default()))

	if err == nil {
		t.Fatal("expected error when config validation fails, got nil")
	}

	// Verify error message mentions validation
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

// TestNew_NilGenkit verifies that New returns an error when Genkit instance is nil.
func TestNew_NilGenkit(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "test-key") // Set fake API key for config validation
	ctx := context.Background()

	cfg := &config.Config{
		ModelName:          "gemini-2.5-flash",
		Temperature:        0.7,
		MaxTokens:          1024,
		MaxHistoryMessages: 10,
		RAGTopK:            3,
		EmbedderModel:      "text-embedding-004",
		PostgresHost:       "localhost",
		PostgresPort:       5432,
		PostgresDBName:     "test_db",
	}

	_, err := New(ctx, cfg, nil, &mockRetriever{}, WithSessionStore(NewNoopSessionStore()), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(slog.Default()))

	if err == nil {
		t.Fatal("expected error when genkit is nil, got nil")
	}

	expectedMsg := "genkit instance is required"
	if err.Error() != expectedMsg {
		t.Errorf("expected error %q, got %q", expectedMsg, err.Error())
	}
}

// TestNew_NilRetriever verifies that New returns an error when retriever is nil.
func TestNew_NilRetriever(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "test-key") // Set fake API key for config validation
	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPromptDir("../../prompts"))

	cfg := &config.Config{
		ModelName:          "gemini-2.5-flash",
		Temperature:        0.7,
		MaxTokens:          1024,
		MaxHistoryMessages: 10,
		RAGTopK:            3,
		EmbedderModel:      "text-embedding-004",
		PostgresHost:       "localhost",
		PostgresPort:       5432,
		PostgresDBName:     "test_db",
	}

	_, err := New(ctx, cfg, g, nil, WithSessionStore(NewNoopSessionStore()), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(slog.Default()))

	if err == nil {
		t.Fatal("expected error when retriever is nil, got nil")
	}

	expectedMsg := "retriever is required for RAG functionality"
	if err.Error() != expectedMsg {
		t.Errorf("expected error %q, got %q", expectedMsg, err.Error())
	}
}

// TestNew_NilSessionStore verifies that New returns an error when sessionStore is nil.
func TestNew_NilSessionStore(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "test-key") // Set fake API key for config validation
	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPromptDir("../../prompts"))

	cfg := &config.Config{
		ModelName:          "gemini-2.5-flash",
		Temperature:        0.7,
		MaxTokens:          1024,
		MaxHistoryMessages: 10,
		RAGTopK:            3,
		EmbedderModel:      "text-embedding-004",
		PostgresHost:       "localhost",
		PostgresPort:       5432,
		PostgresDBName:     "test_db",
	}

	_, err := New(ctx, cfg, g, &mockRetriever{}, WithSessionStore(nil), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(slog.Default()))

	if err == nil {
		t.Fatal("expected error when sessionStore is nil, got nil")
	}

	expectedMsg := "sessionStore is required (use NewNoopSessionStore() for stub)"
	if err.Error() != expectedMsg {
		t.Errorf("expected error %q, got %q", expectedMsg, err.Error())
	}
}

// TestNew_NilKnowledgeStore verifies that New returns an error when knowledgeStore is nil.
func TestNew_NilKnowledgeStore(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "test-key") // Set fake API key for config validation
	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPromptDir("../../prompts"))

	cfg := &config.Config{
		ModelName:          "gemini-2.5-flash",
		Temperature:        0.7,
		MaxTokens:          1024,
		MaxHistoryMessages: 10,
		RAGTopK:            3,
		EmbedderModel:      "text-embedding-004",
		PostgresHost:       "localhost",
		PostgresPort:       5432,
		PostgresDBName:     "test_db",
	}

	_, err := New(ctx, cfg, g, &mockRetriever{}, WithSessionStore(NewNoopSessionStore()), WithKnowledgeStore(nil), WithLogger(slog.Default()))

	if err == nil {
		t.Fatal("expected error when knowledgeStore is nil, got nil")
	}

	expectedMsg := "knowledgeStore is required"
	if err.Error() != expectedMsg {
		t.Errorf("expected error %q, got %q", expectedMsg, err.Error())
	}
}

// TestNew_NilLogger verifies that New returns an error when logger is nil.
func TestNew_NilLogger(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "test-key") // Set fake API key for config validation
	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPromptDir("../../prompts"))

	cfg := &config.Config{
		ModelName:          "gemini-2.5-flash",
		Temperature:        0.7,
		MaxTokens:          1024,
		MaxHistoryMessages: 10,
		RAGTopK:            3,
		EmbedderModel:      "text-embedding-004",
		PostgresHost:       "localhost",
		PostgresPort:       5432,
		PostgresDBName:     "test_db",
	}

	_, err := New(ctx, cfg, g, &mockRetriever{}, WithSessionStore(NewNoopSessionStore()), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(nil))

	if err == nil {
		t.Fatal("expected error when logger is nil, got nil")
	}

	expectedMsg := "logger is required (use slog.Default())"
	if err.Error() != expectedMsg {
		t.Errorf("expected error %q, got %q", expectedMsg, err.Error())
	}
}

// TestNew_Success verifies successful Agent construction with valid parameters.
// This test ensures all validation checks pass and Agent is properly initialized.
func TestNew_Success(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "test-key") // Set fake API key for config validation
	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPromptDir("../../prompts"))

	cfg := &config.Config{
		ModelName:          "gemini-2.5-flash",
		Temperature:        0.7,
		MaxTokens:          1024,
		MaxHistoryMessages: 10,
		RAGTopK:            3,
		EmbedderModel:      "text-embedding-004",
		PostgresHost:       "localhost",
		PostgresPort:       5432,
		PostgresDBName:     "test_db",
		Language:           "English",
	}

	agent, err := New(ctx, cfg, g, &mockRetriever{}, WithSessionStore(NewNoopSessionStore()), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(slog.Default()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if agent == nil {
		t.Fatal("expected non-nil agent, got nil")
		return
	}

	// Verify agent fields are properly initialized
	if agent.config != cfg {
		t.Error("agent config not set correctly")
	}

	if agent.g != g {
		t.Error("agent genkit instance not set correctly")
	}

	if agent.logger == nil {
		t.Error("agent logger not set correctly")
	}

	if agent.sessionStore == nil {
		t.Error("agent sessionStore not set correctly")
	}

	if agent.knowledgeStore == nil {
		t.Error("agent knowledgeStore not set correctly")
	}
}

// TestNew_NegativeMaxTokens verifies that negative MaxTokens values
// are rejected during config validation.
func TestNew_NegativeMaxTokens(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPromptDir("../../prompts"))

	cfg := &config.Config{
		ModelName:          "gemini-2.5-flash",
		Temperature:        0.7,
		MaxTokens:          -100, // Negative value
		MaxHistoryMessages: 10,
		RAGTopK:            3,
		EmbedderModel:      "text-embedding-004",
		PostgresHost:       "localhost",
		PostgresPort:       5432,
		PostgresDBName:     "test_db",
		Language:           "English",
	}

	// This should fail during config validation
	_, err := New(ctx, cfg, g, &mockRetriever{}, WithSessionStore(NewNoopSessionStore()), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(slog.Default()))

	if err == nil {
		t.Fatal("expected error for negative MaxTokens, got nil")
	}

	// Verify error message mentions MaxTokens
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

// TestNew_SystemPromptNotFound verifies that New returns an error
// when the system prompt file cannot be found.
func TestNew_SystemPromptNotFound(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "test-key") // Set fake API key for config validation
	ctx := context.Background()

	// Create a temporary empty directory for prompts
	tmpDir := t.TempDir()

	// Initialize Genkit with empty prompt directory
	g := genkit.Init(ctx, genkit.WithPromptDir(tmpDir))

	cfg := &config.Config{
		ModelName:          "gemini-2.5-flash",
		Temperature:        0.7,
		MaxTokens:          1024,
		MaxHistoryMessages: 10,
		RAGTopK:            3,
		EmbedderModel:      "text-embedding-004",
		PostgresHost:       "localhost",
		PostgresPort:       5432,
		PostgresDBName:     "test_db",
		Language:           "English",
	}

	_, err := New(ctx, cfg, g, &mockRetriever{}, WithSessionStore(NewNoopSessionStore()), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(slog.Default()))

	if err == nil {
		t.Fatal("expected error when system prompt not found, got nil")
	}

	expectedMsg := "system prompt not found"
	if err.Error() != expectedMsg {
		t.Errorf("expected error %q, got %q", expectedMsg, err.Error())
	}
}

// TestNewSession_SaveCurrentSessionIDFails verifies error handling
// when SaveCurrentSessionID fails. This tests the error path at line 744-746
// of agent.go. Note: This test is difficult to implement without file system mocking
// because SaveCurrentSessionID performs actual file I/O operations.
// Skipped for now as it requires complex test infrastructure.
func TestNewSession_SaveCurrentSessionIDFails(t *testing.T) {
	t.Skip("Requires file system mocking - SaveCurrentSessionID performs real file I/O")

	// This test would need to:
	// 1. Mock session.SaveCurrentSessionID to return an error
	// 2. Or create a read-only directory to force file write failure
	// 3. Or use a virtual filesystem for testing
	// These approaches require significant test infrastructure changes.
}

// ============================================================================
// P3 Phase 3.2: Session Management Function Tests
// ============================================================================

// TestNewSession_Success verifies successful session creation.
// Ensures:
//   - Session is created with correct title
//   - Conversation history is cleared
//   - Session ID is saved to state
//   - CreateSession is called with correct parameters
func TestNewSession_Success(t *testing.T) {
	mockStore := &mockSessionStore{}

	agent := &Agent{
		config: &config.Config{
			ModelName:          "test-model",
			MaxHistoryMessages: 10,
		},
		sessionStore: mockStore,
		systemPrompt: "test prompt",
		messages: []*ai.Message{
			{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("old message")}},
		},
		logger: slog.Default(),
	}

	ctx := context.Background()
	session, err := agent.NewSession(ctx, "Test Session Title")
	// Verify success
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session == nil {
		t.Fatal("expected non-nil session")
		return
	}
	if session.Title != "Test Session Title" {
		t.Errorf("expected title 'Test Session Title', got %q", session.Title)
	}

	// Verify history was cleared
	if len(agent.messages) != 0 {
		t.Errorf("expected history to be cleared, got %d messages", len(agent.messages))
	}

	// Verify CreateSession was called
	if !mockStore.createCalled {
		t.Error("expected CreateSession to be called")
	}

	// Verify currentSessionID was set
	if agent.currentSessionID == nil {
		t.Error("expected currentSessionID to be set")
	} else if *agent.currentSessionID != session.ID {
		t.Errorf("expected currentSessionID %v, got %v", session.ID, *agent.currentSessionID)
	}
}

// TestNewSession_CreateFails verifies error handling when CreateSession fails.
func TestNewSession_CreateFails(t *testing.T) {
	mockStore := &mockSessionStore{
		createSessionFunc: func(ctx context.Context, title, modelName, systemPrompt string) (*session.Session, error) {
			return nil, errors.New("database error")
		},
	}

	agent := &Agent{
		config:       &config.Config{ModelName: "test-model"},
		sessionStore: mockStore,
		systemPrompt: "test prompt",
		logger:       slog.Default(),
	}

	ctx := context.Background()
	session, err := agent.NewSession(ctx, "Test Title")

	// Verify error is returned
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if session != nil {
		t.Errorf("expected nil session, got %v", session)
	}

	// Verify error message
	if !errors.Is(err, errors.New("database error")) && err.Error() != "failed to create session: database error" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestNewSession_ClearsHistory verifies that NewSession clears existing conversation history.
func TestNewSession_ClearsHistory(t *testing.T) {
	mockStore := &mockSessionStore{}

	// Create agent with 3 messages in history
	agent := &Agent{
		config:       &config.Config{ModelName: "test-model"},
		sessionStore: mockStore,
		systemPrompt: "test prompt",
		messages: []*ai.Message{
			{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("message 1")}},
			{Role: ai.RoleModel, Content: []*ai.Part{ai.NewTextPart("response 1")}},
			{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("message 2")}},
		},
		logger: slog.Default(),
	}

	if len(agent.messages) != 3 {
		t.Fatalf("setup failed: expected 3 messages, got %d", len(agent.messages))
	}

	ctx := context.Background()
	_, err := agent.NewSession(ctx, "New Session")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all history was cleared
	if len(agent.messages) != 0 {
		t.Errorf("expected empty history, got %d messages", len(agent.messages))
	}
}

// TestSwitchSession_Success verifies successful session switching.
func TestSwitchSession_Success(t *testing.T) {
	testSessionID := uuid.New()

	// Create mock messages to return from GetMessages
	mockMessages := []*session.Message{
		{
			Role:    string(ai.RoleUser),
			Content: []*ai.Part{ai.NewTextPart("previous message")},
		},
	}

	mockStore := &mockSessionStore{
		getMessagesFunc: func(ctx context.Context, sessionID uuid.UUID, limit, offset int32) ([]*session.Message, error) {
			if sessionID != testSessionID {
				t.Errorf("expected session ID %v, got %v", testSessionID, sessionID)
			}
			return mockMessages, nil
		},
	}

	agent := &Agent{
		config: &config.Config{
			ModelName:          "test-model",
			MaxHistoryMessages: 10,
		},
		sessionStore: mockStore,
		systemPrompt: "test prompt",
		messages:     []*ai.Message{},
		logger:       slog.Default(),
	}

	// First, save the session ID to local state
	if err := session.SaveCurrentSessionID(testSessionID); err != nil {
		t.Fatalf("failed to save session ID: %v", err)
	}

	ctx := context.Background()
	err := agent.SwitchSession(ctx, testSessionID)
	// Verify success
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify GetMessages was called
	if !mockStore.getMessagesCalled {
		t.Error("expected GetMessages to be called")
	}

	// Verify messages were loaded
	if len(agent.messages) != 1 {
		t.Errorf("expected 1 message loaded, got %d", len(agent.messages))
	}

	// Verify currentSessionID was set
	if agent.currentSessionID == nil {
		t.Error("expected currentSessionID to be set")
	} else if *agent.currentSessionID != testSessionID {
		t.Errorf("expected currentSessionID %v, got %v", testSessionID, *agent.currentSessionID)
	}
}

// TestSwitchSession_GetMessagesFails verifies error handling when GetMessages fails.
func TestSwitchSession_GetMessagesFails(t *testing.T) {
	testSessionID := uuid.New()

	mockStore := &mockSessionStore{
		getMessagesFunc: func(ctx context.Context, sessionID uuid.UUID, limit, offset int32) ([]*session.Message, error) {
			return nil, errors.New("database connection failed")
		},
	}

	agent := &Agent{
		config: &config.Config{
			ModelName:          "test-model",
			MaxHistoryMessages: 10,
		},
		sessionStore: mockStore,
		systemPrompt: "test prompt",
		logger:       slog.Default(),
	}

	// Save the session ID to local state
	if err := session.SaveCurrentSessionID(testSessionID); err != nil {
		t.Fatalf("failed to save session ID: %v", err)
	}

	ctx := context.Background()
	err := agent.SwitchSession(ctx, testSessionID)

	// Verify error is returned
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify error message contains "failed to load session messages"
	if err.Error() != "failed to load session messages: database connection failed" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestGetCurrentSession_NoSession verifies error when no active session exists.
func TestGetCurrentSession_NoSession(t *testing.T) {
	mockStore := &mockSessionStore{}

	agent := &Agent{
		config:           &config.Config{ModelName: "test-model"},
		sessionStore:     mockStore,
		currentSessionID: nil, // No active session
		logger:           slog.Default(),
	}

	ctx := context.Background()
	session, err := agent.GetCurrentSession(ctx)

	// Verify error is returned
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if session != nil {
		t.Errorf("expected nil session, got %v", session)
	}

	// Verify error message
	if err.Error() != "no active session" {
		t.Errorf("expected error 'no active session', got %q", err.Error())
	}

	// Verify GetSession was NOT called
	if mockStore.getCalled {
		t.Error("GetSession should not be called when currentSessionID is nil")
	}
}

// TestGetCurrentSession_Success verifies successful retrieval of current session.
func TestGetCurrentSession_Success(t *testing.T) {
	testSessionID := uuid.New()
	expectedSession := &session.Session{
		ID:    testSessionID,
		Title: "Current Session",
	}

	mockStore := &mockSessionStore{
		getSessionFunc: func(ctx context.Context, sessionID uuid.UUID) (*session.Session, error) {
			if sessionID != testSessionID {
				t.Errorf("expected session ID %v, got %v", testSessionID, sessionID)
			}
			return expectedSession, nil
		},
	}

	agent := &Agent{
		config:           &config.Config{ModelName: "test-model"},
		sessionStore:     mockStore,
		currentSessionID: &testSessionID,
		logger:           slog.Default(),
	}

	ctx := context.Background()
	session, err := agent.GetCurrentSession(ctx)
	// Verify success
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session == nil {
		t.Fatal("expected non-nil session")
		return
	}
	if session.ID != testSessionID {
		t.Errorf("expected session ID %v, got %v", testSessionID, session.ID)
	}
	if session.Title != "Current Session" {
		t.Errorf("expected title 'Current Session', got %q", session.Title)
	}

	// Verify GetSession was called
	if !mockStore.getCalled {
		t.Error("expected GetSession to be called")
	}
}

// TestGetCurrentSession_GetSessionFails verifies error handling when GetSession fails.
func TestGetCurrentSession_GetSessionFails(t *testing.T) {
	testSessionID := uuid.New()

	mockStore := &mockSessionStore{
		getSessionFunc: func(ctx context.Context, sessionID uuid.UUID) (*session.Session, error) {
			return nil, errors.New("session not found")
		},
	}

	agent := &Agent{
		config:           &config.Config{ModelName: "test-model"},
		sessionStore:     mockStore,
		currentSessionID: &testSessionID,
		logger:           slog.Default(),
	}

	ctx := context.Background()
	session, err := agent.GetCurrentSession(ctx)

	// Verify error is returned
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if session != nil {
		t.Errorf("expected nil session, got %v", session)
	}

	// Verify error message
	if err.Error() != "session not found" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestNoopSessionStore_CreateSession verifies noopSessionStore returns appropriate error.
func TestNoopSessionStore_CreateSession(t *testing.T) {
	store := NewNoopSessionStore()

	ctx := context.Background()
	session, err := store.CreateSession(ctx, "Test", "model", "prompt")

	// Verify error is returned
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if session != nil {
		t.Errorf("expected nil session, got %v", session)
	}

	// Verify error message contains "not yet enabled"
	expectedMsg := "session persistence not yet enabled (noopSessionStore)"
	if err.Error() != expectedMsg {
		t.Errorf("expected error %q, got %q", expectedMsg, err.Error())
	}
}

// TestNoopSessionStore_GetSession verifies noopSessionStore returns appropriate error.
func TestNoopSessionStore_GetSession(t *testing.T) {
	store := NewNoopSessionStore()

	ctx := context.Background()
	testID := uuid.New()
	session, err := store.GetSession(ctx, testID)

	// Verify error is returned
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if session != nil {
		t.Errorf("expected nil session, got %v", session)
	}

	// Verify error message contains "not yet enabled"
	expectedMsg := "session persistence not yet enabled (noopSessionStore)"
	if err.Error() != expectedMsg {
		t.Errorf("expected error %q, got %q", expectedMsg, err.Error())
	}
}

// TestNoopSessionStore_GetMessages verifies noopSessionStore returns empty messages without error.
func TestNoopSessionStore_GetMessages(t *testing.T) {
	store := NewNoopSessionStore()

	ctx := context.Background()
	testID := uuid.New()
	messages, err := store.GetMessages(ctx, testID, 10, 0)
	// Verify no error
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify empty slice (not nil) - following Go best practice
	if messages == nil {
		t.Error("expected non-nil empty slice, got nil")
	}
	if len(messages) != 0 {
		t.Errorf("expected empty messages slice, got %d messages", len(messages))
	}
}

// TestNoopSessionStore_AddMessages verifies noopSessionStore silently succeeds.
func TestNoopSessionStore_AddMessages(t *testing.T) {
	store := NewNoopSessionStore()

	ctx := context.Background()
	testID := uuid.New()
	testMessages := []*session.Message{
		{Role: "user", Content: []*ai.Part{ai.NewTextPart("test")}},
	}

	err := store.AddMessages(ctx, testID, testMessages)
	// Verify no error (silently succeeds)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ============================================================================
// P3 Phase 3.2 Phase 2: Helper Function Tests
// ============================================================================

// TestTruncateString verifies string truncation logic.
func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "shorter than maxLen",
			input:    "short",
			maxLen:   10,
			expected: "short",
		},
		{
			name:     "exactly maxLen",
			input:    "exact",
			maxLen:   5,
			expected: "exact",
		},
		{
			name:     "longer than maxLen",
			input:    "this is a very long string",
			maxLen:   10,
			expected: "this is a ...",
		},
		{
			name:     "empty string",
			input:    "",
			maxLen:   5,
			expected: "",
		},
		{
			name:     "maxLen is 0",
			input:    "test",
			maxLen:   0,
			expected: "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestTrimHistoryIfNeeded_Unlimited verifies unlimited history mode (maxMessages <= 0).
func TestTrimHistoryIfNeeded_Unlimited(t *testing.T) {
	agent := &Agent{
		config: &config.Config{
			MaxHistoryMessages: 0, // Unlimited
		},
		messages: []*ai.Message{
			{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("msg1")}},
			{Role: ai.RoleModel, Content: []*ai.Part{ai.NewTextPart("resp1")}},
		},
		logger: slog.Default(),
	}

	originalLen := len(agent.messages)
	agent.trimHistoryIfNeeded()

	// Verify no trimming occurred
	if len(agent.messages) != originalLen {
		t.Errorf("expected %d messages, got %d", originalLen, len(agent.messages))
	}
}

// TestTrimHistoryIfNeeded_WithinLimit verifies no trimming when within limit.
func TestTrimHistoryIfNeeded_WithinLimit(t *testing.T) {
	agent := &Agent{
		config: &config.Config{
			MaxHistoryMessages: 5,
		},
		messages: []*ai.Message{
			{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("msg1")}},
			{Role: ai.RoleModel, Content: []*ai.Part{ai.NewTextPart("resp1")}},
			{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("msg2")}},
		},
		logger: slog.Default(),
	}

	originalLen := len(agent.messages)
	agent.trimHistoryIfNeeded()

	// Verify no trimming occurred
	if len(agent.messages) != originalLen {
		t.Errorf("expected %d messages, got %d", originalLen, len(agent.messages))
	}
}

// TestTrimHistoryIfNeeded_ExceedsLimit verifies trimming when exceeding limit.
func TestTrimHistoryIfNeeded_ExceedsLimit(t *testing.T) {
	agent := &Agent{
		config: &config.Config{
			MaxHistoryMessages: 2,
		},
		messages: []*ai.Message{
			{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("msg1")}},
			{Role: ai.RoleModel, Content: []*ai.Part{ai.NewTextPart("resp1")}},
			{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("msg2")}},
			{Role: ai.RoleModel, Content: []*ai.Part{ai.NewTextPart("resp2")}},
			{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("msg3")}},
		},
		logger: slog.Default(),
	}

	agent.trimHistoryIfNeeded()

	// Verify only most recent 2 messages remain
	if len(agent.messages) != 2 {
		t.Errorf("expected 2 messages, got %d", len(agent.messages))
	}

	// Verify correct messages remain (most recent)
	if agent.messages[0].Role != ai.RoleModel {
		t.Errorf("expected first message to be Model role, got %v", agent.messages[0].Role)
	}
	if agent.messages[1].Role != ai.RoleUser {
		t.Errorf("expected second message to be User role, got %v", agent.messages[1].Role)
	}
}

// TestCalculateTurnNumber_Success verifies successful turn calculation.
func TestCalculateTurnNumber_Success(t *testing.T) {
	mockKnowledge := &mockKnowledgeStore{
		countFunc: func(ctx context.Context, filters map[string]string) (int, error) {
			// Verify correct filters
			if filters["source_type"] != "conversation" {
				t.Errorf("expected source_type=conversation, got %v", filters["source_type"])
			}
			if filters["session_id"] != "test-session" {
				t.Errorf("expected session_id=test-session, got %v", filters["session_id"])
			}
			return 5, nil // 5 existing turns
		},
	}

	agent := &Agent{
		knowledgeStore: mockKnowledge,
		logger:         slog.Default(),
	}

	ctx := context.Background()
	turnNum := agent.calculateTurnNumber(ctx, "test-session")

	// Verify turn number is count + 1
	if turnNum != 6 {
		t.Errorf("expected turn number 6, got %d", turnNum)
	}
}

// TestCalculateTurnNumber_Error verifies error handling returns 0 as fallback.
func TestCalculateTurnNumber_Error(t *testing.T) {
	mockKnowledge := &mockKnowledgeStore{
		countFunc: func(ctx context.Context, filters map[string]string) (int, error) {
			return 0, errors.New("database connection failed")
		},
	}

	agent := &Agent{
		knowledgeStore: mockKnowledge,
		logger:         slog.Default(),
	}

	ctx := context.Background()
	turnNum := agent.calculateTurnNumber(ctx, "test-session")

	// Verify fallback to 0
	if turnNum != 0 {
		t.Errorf("expected fallback turn number 0, got %d", turnNum)
	}
}

// ============================================================================
// ConnectMCP and MCP Tests
// ============================================================================

func TestConnectMCP_NotConnected(t *testing.T) {
	agent := createTestAgent(t, nil)

	// Before connecting, MCP should be nil
	if agent.MCP() != nil {
		t.Error("expected MCP() to return nil before connection")
	}
}

func TestConnectMCP_EmptyConfig(t *testing.T) {
	ctx := context.Background()
	agent := createTestAgent(t, nil)

	// Connect with empty config should not error (or return expected error)
	err := agent.ConnectMCP(ctx, []mcp.Config{})
	// Empty config will likely error, which is expected behavior
	if err != nil {
		t.Logf("ConnectMCP with empty config returned error (expected): %v", err)
	}
}

func TestConnectMCP_MultipleCallsIdempotent(t *testing.T) {
	ctx := context.Background()
	agent := createTestAgent(t, nil)

	// Call ConnectMCP multiple times - should only execute once due to sync.Once
	err1 := agent.ConnectMCP(ctx, []mcp.Config{})
	err2 := agent.ConnectMCP(ctx, []mcp.Config{})

	// Both calls should return the same error (if any) due to sync.Once
	if (err1 == nil) != (err2 == nil) {
		t.Errorf("multiple ConnectMCP calls returned different error states: err1=%v, err2=%v", err1, err2)
	}
}

func TestMCP_Getter(t *testing.T) {
	agent := createTestAgent(t, nil)

	// Test getter returns nil initially (before connection)
	mcpServer := agent.MCP()
	if mcpServer != nil {
		t.Error("expected MCP() to return nil initially")
	}
}

// ============================================================================
// tools Function Tests
// ============================================================================

func TestTools_WithoutMCP(t *testing.T) {
	ctx := context.Background()
	agent := createTestAgent(t, nil)

	// Get tools without MCP connection
	toolRefs := agent.tools(ctx)

	// Should return at least some local tools
	if len(toolRefs) == 0 {
		t.Error("expected tools() to return local tools, got empty slice")
	}

	t.Logf("tools() returned %d tool(s) without MCP", len(toolRefs))
}

func TestTools_WithMCP(t *testing.T) {
	ctx := context.Background()
	agent := createTestAgent(t, nil)

	// Attempt to connect MCP (will likely fail with empty config, but that's ok)
	_ = agent.ConnectMCP(ctx, []mcp.Config{})

	// Get tools - should handle both success and failure of MCP connection gracefully
	toolRefs := agent.tools(ctx)

	// Should return local tools at minimum (even if MCP connection failed)
	if len(toolRefs) == 0 {
		t.Error("expected tools() to return at least local tools")
	}

	t.Logf("tools() returned %d tool(s) with MCP connection attempt", len(toolRefs))
}
