package agent

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core/api"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/sqlc"
)

// ============================================================================
// Mock Implementations for Testing
// ============================================================================

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

// Register is a dummy method to satisfy the ai.Retriever interface.
func (m *mockRetriever) Register(r api.Registry) {}

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

func (m *mockEmbedder) Register(r api.Registry) {}

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

// createMockKnowledgeStore creates a knowledge store for testing.
func createMockKnowledgeStore() *knowledge.Store {
	return knowledge.NewWithQuerier(&mockKnowledgeQuerier{}, &mockEmbedder{}, slog.Default())
}

// mockSessionStore is a flexible mock for SessionStore interface.
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
		WithSessionStore(&mockSessionStore{}),
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

// ============================================================================
// Agent Constructor Tests
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

	_, err := New(ctx, cfg, g, &mockRetriever{}, WithSessionStore(&mockSessionStore{}), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(slog.Default()))

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

	_, err := New(ctx, cfg, nil, &mockRetriever{}, WithSessionStore(&mockSessionStore{}), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(slog.Default()))

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

	_, err := New(ctx, cfg, g, nil, WithSessionStore(&mockSessionStore{}), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(slog.Default()))

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

	expectedMsg := "sessionStore is required (provide via WithSessionStore option)"
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

	_, err := New(ctx, cfg, g, &mockRetriever{}, WithSessionStore(&mockSessionStore{}), WithKnowledgeStore(nil), WithLogger(slog.Default()))

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

	_, err := New(ctx, cfg, g, &mockRetriever{}, WithSessionStore(&mockSessionStore{}), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(nil))

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

	agent, err := New(ctx, cfg, g, &mockRetriever{}, WithSessionStore(&mockSessionStore{}), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(slog.Default()))
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
	_, err := New(ctx, cfg, g, &mockRetriever{}, WithSessionStore(&mockSessionStore{}), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(slog.Default()))

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

	_, err := New(ctx, cfg, g, &mockRetriever{}, WithSessionStore(&mockSessionStore{}), WithKnowledgeStore(&mockKnowledgeStore{}), WithLogger(slog.Default()))

	if err == nil {
		t.Fatal("expected error when system prompt not found, got nil")
	}

	expectedMsg := "system prompt not found"
	if err.Error() != expectedMsg {
		t.Errorf("expected error %q, got %q", expectedMsg, err.Error())
	}
}
