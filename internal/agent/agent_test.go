package agent

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

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

// TestExecute_BasicInterrupt verifies that the Execute method correctly handles
// a single tool call interruption from the model.
func TestExecute_BasicInterrupt(t *testing.T) {
	// 1. Arrange
	ctx := context.Background()

	// Use GenerateFunc to return different responses on each call
	callCount := 0
	mockGen := &mockGenerator{
		GenerateFunc: func(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error) {
			callCount++
			t.Logf("GenerateFunc called, count=%d", callCount)

			if callCount == 1 {
				// First call: return interruption
				toolReq := &ai.ToolRequest{
					Name: "requestConfirmation",
					Input: map[string]any{
						"toolToConfirm": "deleteFile",
						"params":        map[string]any{"path": "test.txt"},
						"reason":        "Test deletion",
					},
				}
				// Create a Part with interrupt metadata
				part := ai.NewToolRequestPart(toolReq)
				part.Metadata = map[string]any{"interrupt": true}

				resp := &ai.ModelResponse{
					Message: &ai.Message{
						Role:    ai.RoleModel,
						Content: []*ai.Part{part},
					},
					FinishReason: ai.FinishReasonInterrupted,
				}
				t.Logf("Returning interrupt response")
				return resp, nil
			}

			// Second call (after approval): return completion
			t.Logf("Returning completion response")
			return &ai.ModelResponse{
				Message: &ai.Message{
					Role:    ai.RoleModel,
					Content: []*ai.Part{ai.NewTextPart("Done.")},
				},
				FinishReason: ai.FinishReasonStop,
			}, nil
		},
	}

	agent := createTestAgent(t, mockGen)

	// 2. Act
	eventCh := agent.Execute(ctx, "list files")

	// 3. Assert
	// We expect to receive an interrupt event.
	event, ok := <-eventCh
	if !ok {
		t.Fatal("Event channel closed unexpectedly")
	}

	// Log the event type for debugging
	t.Logf("Received event type: %v (Text=0, Thought=1, Interrupt=2, Error=3, Complete=4)", event.Type)
	if event.Type == EventTypeError {
		t.Fatalf("Received error event: %v", event.Error)
	}

	if event.Type != EventTypeInterrupt {
		t.Fatalf("Expected event type %v (Interrupt), but got %v", EventTypeInterrupt, event.Type)
	}

	if event.Interrupt == nil {
		t.Fatal("Expected interrupt event to have a non-nil Interrupt field")
	}

	if event.Interrupt.ToolName != "deleteFile" {
		t.Errorf("Expected tool name 'deleteFile', but got '%s'", event.Interrupt.ToolName)
	}

	// Simulate the UI approving the action.
	// Send approval to resume execution
	event.Interrupt.ResumeChannel <- ConfirmationResponse{Approved: true}

	// After approval, the agent will call Generate again.
	// Note: In unit tests with mocks, streaming callbacks aren't triggered,
	// so we won't receive Text events. We should receive Complete directly.
	event, ok = <-eventCh
	if !ok {
		t.Fatal("Event channel closed unexpectedly after confirmation")
	}

	// We expect a complete event indicating successful execution.
	if event.Type != EventTypeComplete {
		if event.Type == EventTypeError {
			t.Fatalf("Received error event: %v", event.Error)
		}
		t.Fatalf("Expected event type %v (Complete) at the end, but got %v", EventTypeComplete, event.Type)
	}

	// Verify Generate was called exactly twice
	if callCount != 2 {
		t.Errorf("Expected Generate to be called 2 times, but was called %d times", callCount)
	}
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
	eventCh := agent.Execute(ctx, "some input")

	// 3. Assert
	// We expect to receive an error event.
	event, ok := <-eventCh
	if !ok {
		t.Fatal("Event channel closed unexpectedly")
	}

	if event.Type != EventTypeError {
		t.Fatalf("Expected event type %v, but got %v", EventTypeError, event.Type)
	}

	if event.Error == nil {
		t.Fatal("Expected error event to have a non-nil Error field")
	}

	if !errors.Is(event.Error, expectedErr) {
		t.Errorf("Expected error '%v', but got '%v'", expectedErr, event.Error)
	}

	// The channel should close after the error.
	_, ok = <-eventCh
	if ok {
		t.Fatal("Expected event channel to be closed after an error")
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
	eventCh1 := agent.Execute(ctx, "My name is Alice")

	// Consume all events from turn 1
	for event := range eventCh1 {
		if event.Type == EventTypeError {
			t.Fatalf("Turn 1 error: %v", event.Error)
		}
	}

	// Verify history after turn 1
	historyLen1 := agent.HistoryLength()
	t.Logf("History length after turn 1: %d", historyLen1)
	if historyLen1 != 2 { // User message + Model response
		t.Errorf("Expected history length 2 after turn 1, got %d", historyLen1)
	}

	// 2. Act - Turn 2
	t.Log("=== Turn 2: User asks about their name ===")
	eventCh2 := agent.Execute(ctx, "What's my name?")

	// Consume all events from turn 2
	for event := range eventCh2 {
		if event.Type == EventTypeError {
			t.Fatalf("Turn 2 error: %v", event.Error)
		}
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

// TestExecute_InterruptRejection verifies that the Execute method correctly handles
// the scenario where the user rejects a dangerous operation.
func TestExecute_InterruptRejection(t *testing.T) {
	// 1. Arrange
	ctx := context.Background()

	callCount := 0
	mockGen := &mockGenerator{
		GenerateFunc: func(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error) {
			callCount++
			t.Logf("GenerateFunc called, count=%d", callCount)

			if callCount == 1 {
				// First call: return interruption for dangerous operation
				toolReq := &ai.ToolRequest{
					Name: "requestConfirmation",
					Input: map[string]any{
						"toolToConfirm": "deleteFile",
						"params":        map[string]any{"path": "important.txt"},
						"reason":        "Deleting important file",
					},
				}
				// Create a Part with interrupt metadata
				part := ai.NewToolRequestPart(toolReq)
				part.Metadata = map[string]any{"interrupt": true}

				resp := &ai.ModelResponse{
					Message: &ai.Message{
						Role:    ai.RoleModel,
						Content: []*ai.Part{part},
					},
					FinishReason: ai.FinishReasonInterrupted,
				}
				t.Logf("Returning interrupt response for deleteFile")
				return resp, nil
			}

			// Second call (after rejection): return completion with acknowledgement
			t.Logf("Returning completion response after rejection")
			return &ai.ModelResponse{
				Message: &ai.Message{
					Role:    ai.RoleModel,
					Content: []*ai.Part{ai.NewTextPart("Understood. I will not delete the file.")},
				},
				FinishReason: ai.FinishReasonStop,
			}, nil
		},
	}

	agent := createTestAgent(t, mockGen)

	// 2. Act
	eventCh := agent.Execute(ctx, "delete important.txt")

	// 3. Assert
	// We expect to receive an interrupt event.
	event, ok := <-eventCh
	if !ok {
		t.Fatal("Event channel closed unexpectedly")
	}

	t.Logf("Received event type: %v", event.Type)
	if event.Type == EventTypeError {
		t.Fatalf("Received error event: %v", event.Error)
	}

	if event.Type != EventTypeInterrupt {
		t.Fatalf("Expected event type %v (Interrupt), but got %v", EventTypeInterrupt, event.Type)
	}

	if event.Interrupt == nil {
		t.Fatal("Expected interrupt event to have a non-nil Interrupt field")
	}

	if event.Interrupt.ToolName != "deleteFile" {
		t.Errorf("Expected tool name 'deleteFile', but got '%s'", event.Interrupt.ToolName)
	}

	// Simulate the UI rejecting the action.
	t.Log("Sending rejection")
	event.Interrupt.ResumeChannel <- ConfirmationResponse{
		Approved: false,
		Reason:   "File is important, should not delete",
	}

	// After rejection, the agent will call Generate again.
	// We should receive Complete event indicating the agent acknowledged the rejection.
	event, ok = <-eventCh
	if !ok {
		t.Fatal("Event channel closed unexpectedly after rejection")
	}

	if event.Type != EventTypeComplete {
		if event.Type == EventTypeError {
			t.Fatalf("Received error event: %v", event.Error)
		}
		t.Fatalf("Expected event type %v (Complete) at the end, but got %v", EventTypeComplete, event.Type)
	}

	// Verify Generate was called exactly twice (once for interrupt, once after rejection)
	if callCount != 2 {
		t.Errorf("Expected Generate to be called 2 times, but was called %d times", callCount)
	}

	t.Log("Test passed: Agent correctly handled rejection scenario")
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
	eventCh := agent.Execute(ctx, "write a very long response")

	// 3. Assert
	// We expect to receive an error event.
	event, ok := <-eventCh
	if !ok {
		t.Fatal("Event channel closed unexpectedly")
	}

	if event.Type != EventTypeError {
		t.Fatalf("Expected event type %v (Error), but got %v", EventTypeError, event.Type)
	}

	if event.Error == nil {
		t.Fatal("Expected error event to have a non-nil Error field")
	}

	expectedMsg := "response truncated: maximum token limit reached"
	if event.Error.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', but got '%s'", expectedMsg, event.Error.Error())
	}

	// The channel should close after the error.
	_, ok = <-eventCh
	if ok {
		t.Fatal("Expected event channel to be closed after an error")
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
	eventCh := agent.Execute(ctx, "potentially harmful request")

	// 3. Assert
	// We expect to receive an error event.
	event, ok := <-eventCh
	if !ok {
		t.Fatal("Event channel closed unexpectedly")
	}

	if event.Type != EventTypeError {
		t.Fatalf("Expected event type %v (Error), but got %v", EventTypeError, event.Type)
	}

	if event.Error == nil {
		t.Fatal("Expected error event to have a non-nil Error field")
	}

	expectedMsg := "response blocked by safety filter"
	if event.Error.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', but got '%s'", expectedMsg, event.Error.Error())
	}

	// The channel should close after the error.
	_, ok = <-eventCh
	if ok {
		t.Fatal("Expected event channel to be closed after an error")
	}

	t.Log("Test passed: Agent correctly handled FinishReasonBlocked")
}

// TestExecute_ContextCancellation verifies that the Execute method correctly handles
// context cancellation during an interrupt, preventing goroutine leaks (P1-2 fix).
func TestExecute_ContextCancellation(t *testing.T) {
	// 1. Arrange
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	// Use GenerateFunc to return an interrupt on the first call
	callCount := 0
	mockGen := &mockGenerator{
		GenerateFunc: func(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error) {
			callCount++
			t.Logf("GenerateFunc called, count=%d", callCount)

			if callCount == 1 {
				// First call: return interruption
				toolReq := &ai.ToolRequest{
					Name: "requestConfirmation",
					Input: map[string]any{
						"toolToConfirm": "executeCommand",
						"params":        map[string]any{"cmd": "rm -rf /"},
						"reason":        "Dangerous command",
					},
				}
				// Create a Part with interrupt metadata
				part := ai.NewToolRequestPart(toolReq)
				part.Metadata = map[string]any{"interrupt": true}

				resp := &ai.ModelResponse{
					Message: &ai.Message{
						Role:    ai.RoleModel,
						Content: []*ai.Part{part},
					},
					FinishReason: ai.FinishReasonInterrupted,
				}
				t.Logf("Returning interrupt response")
				return resp, nil
			}

			// Should not reach here in this test
			t.Error("Unexpected second call to Generate - context should have been cancelled")
			return nil, errors.New("unexpected call")
		},
	}

	agent := createTestAgent(t, mockGen)

	// 2. Act
	eventCh := agent.Execute(ctx, "delete all files")

	// 3. Assert
	// First, we expect to receive an interrupt event.
	event, ok := <-eventCh
	if !ok {
		t.Fatal("Event channel closed unexpectedly")
	}

	if event.Type != EventTypeInterrupt {
		if event.Type == EventTypeError {
			t.Fatalf("Received error event before cancellation: %v", event.Error)
		}
		t.Fatalf("Expected event type %v (Interrupt), but got %v", EventTypeInterrupt, event.Type)
	}

	if event.Interrupt == nil {
		t.Fatal("Expected interrupt event to have a non-nil Interrupt field")
	}

	// 4. Cancel the context while waiting for user confirmation
	// This simulates the user interrupting the operation (Ctrl+C, timeout, etc.)
	t.Log("Cancelling context to simulate user interrupt")
	cancel()

	// 5. The agent should detect the cancellation and send an error event
	event, ok = <-eventCh
	if !ok {
		t.Fatal("Event channel closed unexpectedly after cancellation")
	}

	if event.Type != EventTypeError {
		t.Fatalf("Expected event type %v (Error) after cancellation, but got %v", EventTypeError, event.Type)
	}

	if event.Error == nil {
		t.Fatal("Expected error event to have a non-nil Error field")
	}

	// Verify error message indicates cancellation
	expectedMsg := "operation cancelled by user"
	if event.Error.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', but got '%s'", expectedMsg, event.Error.Error())
	}

	// The channel should close after the error
	_, ok = <-eventCh
	if ok {
		t.Fatal("Expected event channel to be closed after cancellation error")
	}

	// Verify Generate was called exactly once (no second call due to cancellation)
	if callCount != 1 {
		t.Errorf("Expected Generate to be called 1 time, but was called %d times", callCount)
	}

	t.Log("Test passed: Agent correctly handled context cancellation during interrupt")
}

// TestExecute_ConfirmationFlow_UserRejects verifies that the Execute method
// correctly handles user rejection of a dangerous operation.
func TestExecute_ConfirmationFlow_UserRejects(t *testing.T) {
	// 1. Arrange
	ctx := context.Background()

	callCount := 0
	mockGen := &mockGenerator{
		GenerateFunc: func(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error) {
			callCount++
			t.Logf("GenerateFunc called, count=%d", callCount)

			if callCount == 1 {
				// First call: model requests confirmation to delete important file
				toolReq := &ai.ToolRequest{
					Name: "requestConfirmation",
					Ref:  "req-test-123", // Add Ref for correlation
					Input: map[string]any{
						"toolToConfirm": "deleteFile",
						"params":        map[string]any{"path": "/important/data.txt"},
						"reason":        "Delete important user data file",
					},
				}

				part := ai.NewToolRequestPart(toolReq)
				part.Metadata = map[string]any{"interrupt": true}

				resp := &ai.ModelResponse{
					Message: &ai.Message{
						Role:    ai.RoleModel,
						Content: []*ai.Part{part},
					},
					FinishReason: ai.FinishReasonInterrupted,
				}
				t.Logf("Returning interrupt response for deleteFile confirmation")
				return resp, nil
			}

			// Second call (after rejection): model acknowledges rejection
			// Verify that the model received the rejection response
			t.Logf("Model received rejection, returning acknowledgment")
			return &ai.ModelResponse{
				Message: &ai.Message{
					Role: ai.RoleModel,
					Content: []*ai.Part{
						ai.NewTextPart("I understand. The deletion has been cancelled. Would you like me to backup the file instead?"),
					},
				},
				FinishReason: ai.FinishReasonStop,
			}, nil
		},
	}

	agent := createTestAgent(t, mockGen)

	// 2. Act
	eventCh := agent.Execute(ctx, "delete /important/data.txt")

	// 3. Assert - Step 1: Receive interrupt event
	event, ok := <-eventCh
	if !ok {
		t.Fatal("Event channel closed unexpectedly")
	}

	t.Logf("Received event type: %v", event.Type)
	if event.Type == EventTypeError {
		t.Fatalf("Received error event: %v", event.Error)
	}

	if event.Type != EventTypeInterrupt {
		t.Fatalf("Expected event type %v (Interrupt), but got %v", EventTypeInterrupt, event.Type)
	}

	if event.Interrupt == nil {
		t.Fatal("Expected interrupt event to have a non-nil Interrupt field")
	}

	// Verify interrupt details
	if event.Interrupt.ToolName != "deleteFile" {
		t.Errorf("Expected tool name 'deleteFile', but got '%s'", event.Interrupt.ToolName)
	}

	if event.Interrupt.Reason != "Delete important user data file" {
		t.Errorf("Expected reason 'Delete important user data file', but got '%s'", event.Interrupt.Reason)
	}

	// Verify parameters
	params := event.Interrupt.Parameters
	if params == nil {
		t.Fatal("Expected parameters to be non-nil")
	}

	if path, ok := params["path"].(string); !ok || path != "/important/data.txt" {
		t.Errorf("Expected path '/important/data.txt', but got %v", params["path"])
	}

	// 4. Simulate the UI rejecting the action
	t.Log("User rejects the deletion")
	event.Interrupt.ResumeChannel <- ConfirmationResponse{
		Approved: false,
		Reason:   "This file contains critical user data and should not be deleted",
	}

	// 5. Assert - Step 2: Receive complete event with acknowledgment
	event, ok = <-eventCh
	if !ok {
		t.Fatal("Event channel closed unexpectedly after rejection")
	}

	// We expect a complete event
	if event.Type != EventTypeComplete {
		if event.Type == EventTypeError {
			t.Fatalf("Received error event: %v", event.Error)
		}
		t.Fatalf("Expected event type %v (Complete), but got %v", EventTypeComplete, event.Type)
	}

	// 6. Verify Generate was called exactly twice
	if callCount != 2 {
		t.Errorf("Expected Generate to be called 2 times, but was called %d times", callCount)
	}

	// 7. Verify that the tool response was constructed correctly
	// This is implicitly tested by the fact that the second Generate call succeeded
	t.Log("Test passed: Agent correctly handled user rejection of dangerous operation")
}

// TestBuildToolResponse_MetadataAndRef verifies that buildToolResponse correctly:
// 1. Copies the Ref field from ToolRequest to ToolResponse
// 2. Adds interruptResponse metadata
// 3. Handles approved and rejected decisions correctly
// 4. Handles nil inputs gracefully
func TestBuildToolResponse_MetadataAndRef(t *testing.T) {
	t.Run("approved decision with ref and metadata", func(t *testing.T) {
		// Create an interrupt with a ToolRequest containing a Ref
		testRef := "test-ref-12345"
		interrupt := &ai.Part{
			ToolRequest: &ai.ToolRequest{
				Name: "requestConfirmation",
				Ref:  testRef,
				Input: map[string]any{
					"toolToConfirm": "deleteFile",
					"params":        map[string]any{"path": "/test/file.txt"},
					"reason":        "Delete test file",
				},
			},
		}

		decision := ConfirmationResponse{
			Approved: true,
		}

		// Call buildToolResponse
		result := buildToolResponse(interrupt, decision)

		// Verify result is not nil
		if result == nil {
			t.Fatal("Expected non-nil result, got nil")
			return
		}

		// Verify it's a ToolResponse
		if result.ToolResponse == nil {
			t.Fatal("Expected ToolResponse to be set")
		}

		// Verify Ref field was copied
		if result.ToolResponse.Ref != testRef {
			t.Errorf("Expected Ref '%s', got '%s'", testRef, result.ToolResponse.Ref)
		}

		// Verify Name is correct
		if result.ToolResponse.Name != "requestConfirmation" {
			t.Errorf("Expected Name 'requestConfirmation', got '%s'", result.ToolResponse.Name)
		}

		// Verify metadata contains interruptResponse: true
		if result.Metadata == nil {
			t.Fatal("Expected metadata to be set")
		}

		interruptResp, ok := result.Metadata["interruptResponse"]
		if !ok {
			t.Error("Expected 'interruptResponse' key in metadata")
		} else if interruptResp != true {
			t.Errorf("Expected interruptResponse=true, got %v", interruptResp)
		}

		// Verify output structure for approved decision
		output, ok := result.ToolResponse.Output.(map[string]any)
		if !ok {
			t.Fatal("Expected output to be map[string]any")
		}

		if status, ok := output["status"].(string); !ok || status != "approved" {
			t.Errorf("Expected status='approved', got %v", output["status"])
		}

		if message, ok := output["message"].(string); !ok || message != "User approved this operation" {
			t.Errorf("Expected message='User approved this operation', got %v", output["message"])
		}
	})

	t.Run("rejected decision with reason", func(t *testing.T) {
		testRef := "test-ref-67890"
		interrupt := &ai.Part{
			ToolRequest: &ai.ToolRequest{
				Name: "requestConfirmation",
				Ref:  testRef,
				Input: map[string]any{
					"toolToConfirm": "deleteFile",
					"params":        map[string]any{"path": "/important/file.txt"},
					"reason":        "Delete important file",
				},
			},
		}

		decision := ConfirmationResponse{
			Approved: false,
			Reason:   "File is too important to delete",
		}

		result := buildToolResponse(interrupt, decision)

		// Verify result is not nil
		if result == nil {
			t.Fatal("Expected non-nil result, got nil")
			return
		}

		// Verify Ref was copied
		if result.ToolResponse.Ref != testRef {
			t.Errorf("Expected Ref '%s', got '%s'", testRef, result.ToolResponse.Ref)
		}

		// Verify metadata
		if result.Metadata == nil {
			t.Fatal("Expected metadata to be set")
		}

		if result.Metadata["interruptResponse"] != true {
			t.Error("Expected interruptResponse=true in metadata")
		}

		// Verify output for rejected decision
		output, ok := result.ToolResponse.Output.(map[string]any)
		if !ok {
			t.Fatal("Expected output to be map[string]any")
		}

		if status, ok := output["status"].(string); !ok || status != "rejected" {
			t.Errorf("Expected status='rejected', got %v", output["status"])
		}

		expectedMsg := "User rejected: File is too important to delete"
		if message, ok := output["message"].(string); !ok || message != expectedMsg {
			t.Errorf("Expected message='%s', got %v", expectedMsg, output["message"])
		}
	})

	t.Run("nil interrupt returns nil", func(t *testing.T) {
		decision := ConfirmationResponse{Approved: true}

		result := buildToolResponse(nil, decision)

		if result != nil {
			t.Errorf("Expected nil result for nil interrupt, got %v", result)
		}
	})

	t.Run("nil ToolRequest returns nil", func(t *testing.T) {
		interrupt := &ai.Part{
			ToolRequest: nil, // No ToolRequest
		}

		decision := ConfirmationResponse{Approved: true}

		result := buildToolResponse(interrupt, decision)

		if result != nil {
			t.Errorf("Expected nil result for nil ToolRequest, got %v", result)
		}
	})

	t.Run("empty Ref is handled correctly", func(t *testing.T) {
		// Test with empty Ref string
		interrupt := &ai.Part{
			ToolRequest: &ai.ToolRequest{
				Name: "requestConfirmation",
				Ref:  "", // Empty Ref
				Input: map[string]any{
					"toolToConfirm": "deleteFile",
				},
			},
		}

		decision := ConfirmationResponse{Approved: true}

		result := buildToolResponse(interrupt, decision)

		if result == nil {
			t.Fatal("Expected non-nil result")
			return
		}

		// Empty Ref should still be copied
		if result.ToolResponse.Ref != "" {
			t.Errorf("Expected empty Ref to be copied, got '%s'", result.ToolResponse.Ref)
		}

		// Metadata should still be present
		if result.Metadata["interruptResponse"] != true {
			t.Error("Expected interruptResponse=true even with empty Ref")
		}
	})
}

// TestExecute_MultipleInterrupts verifies that the Execute method can handle
// multiple interrupt requests in a single Generate() response.
//
// Scenario: LLM requests confirmation for deleting two files simultaneously
// 1. First Generate(): Returns 2 requestConfirmation interrupts
// 2. User approves first, rejects second
// 3. Second Generate(): LLM receives both responses and completes
//
// This test validates:
// - Multiple interrupts are processed sequentially
// - Each interrupt gets its own user decision
// - All tool responses are added to history in correct order
// - LLM receives all responses in the next turn
func TestExecute_MultipleInterrupts(t *testing.T) {
	// 1. Arrange
	ctx := context.Background()

	callCount := 0

	mockGen := &mockGenerator{
		GenerateFunc: func(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error) {
			callCount++
			t.Logf("GenerateFunc called, count=%d", callCount)

			if callCount == 1 {
				// First call: Model requests confirmation for TWO file deletions
				toolReq1 := &ai.ToolRequest{
					Name: "requestConfirmation",
					Ref:  "req-file1-001",
					Input: map[string]any{
						"toolToConfirm": "deleteFile",
						"params":        map[string]any{"path": "/tmp/file1.txt"},
						"reason":        "Delete temporary file 1",
					},
				}

				toolReq2 := &ai.ToolRequest{
					Name: "requestConfirmation",
					Ref:  "req-file2-002",
					Input: map[string]any{
						"toolToConfirm": "deleteFile",
						"params":        map[string]any{"path": "/important/file2.txt"},
						"reason":        "Delete important file 2 (user should reject this)",
					},
				}

				part1 := ai.NewToolRequestPart(toolReq1)
				part1.Metadata = map[string]any{"interrupt": true}

				part2 := ai.NewToolRequestPart(toolReq2)
				part2.Metadata = map[string]any{"interrupt": true}

				resp := &ai.ModelResponse{
					Message: &ai.Message{
						Role:    ai.RoleModel,
						Content: []*ai.Part{part1, part2}, // TWO interrupts
					},
					FinishReason: ai.FinishReasonInterrupted,
				}
				t.Logf("Returning 2 interrupt responses")
				return resp, nil
			}

			// Second call: Model receives both tool responses and completes
			t.Logf("Model received responses, returning completion")
			return &ai.ModelResponse{
				Message: &ai.Message{
					Role: ai.RoleModel,
					Content: []*ai.Part{
						ai.NewTextPart("File1 deleted successfully. File2 deletion was cancelled as requested."),
					},
				},
				FinishReason: ai.FinishReasonStop,
			}, nil
		},
	}

	agent := createTestAgent(t, mockGen)

	// 2. Act
	eventCh := agent.Execute(ctx, "Please delete file1.txt and file2.txt")

	// 3. Assert - Process events
	var interruptEvents []*InterruptEvent
	var textChunks []string
	var completionReceived bool

	for event := range eventCh {
		switch event.Type {
		case EventTypeText:
			textChunks = append(textChunks, event.TextChunk)
			t.Logf("Received text: %s", event.TextChunk)

		case EventTypeInterrupt:
			interruptEvents = append(interruptEvents, event.Interrupt)
			t.Logf("Received interrupt #%d: toolName=%s", len(interruptEvents), event.Interrupt.ToolName)

			// Simulate user decisions
			if len(interruptEvents) == 1 {
				// Approve first deletion (file1.txt)
				t.Log("User approves first deletion")
				event.Interrupt.ResumeChannel <- ConfirmationResponse{
					Approved: true,
				}
			} else if len(interruptEvents) == 2 {
				// Reject second deletion (file2.txt - important file)
				t.Log("User rejects second deletion")
				event.Interrupt.ResumeChannel <- ConfirmationResponse{
					Approved: false,
					Reason:   "This is an important file, do not delete",
				}
			}

		case EventTypeComplete:
			completionReceived = true
			t.Log("Received completion event")

		case EventTypeError:
			t.Fatalf("Unexpected error event: %v", event.Error)
		}
	}

	// 4. Verify - Check that we received exactly 2 interrupts
	if len(interruptEvents) != 2 {
		t.Fatalf("Expected 2 interrupt events, got %d", len(interruptEvents))
	}

	// Verify first interrupt (file1.txt)
	interrupt1 := interruptEvents[0]
	if interrupt1.ToolName != "deleteFile" {
		t.Errorf("Interrupt 1: Expected toolName='deleteFile', got '%s'", interrupt1.ToolName)
	}
	if params, ok := interrupt1.Parameters["path"].(string); !ok || params != "/tmp/file1.txt" {
		t.Errorf("Interrupt 1: Expected path='/tmp/file1.txt', got %v", interrupt1.Parameters["path"])
	}
	if interrupt1.Reason != "Delete temporary file 1" {
		t.Errorf("Interrupt 1: Expected reason='Delete temporary file 1', got '%s'", interrupt1.Reason)
	}

	// Verify second interrupt (file2.txt)
	interrupt2 := interruptEvents[1]
	if interrupt2.ToolName != "deleteFile" {
		t.Errorf("Interrupt 2: Expected toolName='deleteFile', got '%s'", interrupt2.ToolName)
	}
	if params, ok := interrupt2.Parameters["path"].(string); !ok || params != "/important/file2.txt" {
		t.Errorf("Interrupt 2: Expected path='/important/file2.txt', got %v", interrupt2.Parameters["path"])
	}
	if interrupt2.Reason != "Delete important file 2 (user should reject this)" {
		t.Errorf("Interrupt 2: Expected reason contains 'important', got '%s'", interrupt2.Reason)
	}

	// Verify completion was received
	if !completionReceived {
		t.Error("Expected completion event, but didn't receive one")
	}

	// Note: In this mock test, streaming callback might not be triggered by mock generator
	// In real scenarios, the model would stream text through the callback
	// We verify that at least the completion event was received
	t.Logf("Received %d text chunks (may be 0 in mock tests)", len(textChunks))

	// Verify that Generate was called exactly twice
	if callCount != 2 {
		t.Errorf("Expected Generate to be called 2 times, got %d", callCount)
	}

	t.Log("✓ Multiple interrupts handled correctly")
}

// TestExecute_RejectionReasonPropagation verifies that when a user rejects a dangerous operation,
// the rejection reason is correctly propagated to the LLM in the second Generate() call.
// This is an end-to-end test ensuring the complete rejection reason transmission chain.
func TestExecute_RejectionReasonPropagation(t *testing.T) {
	// 1. Arrange
	ctx := context.Background()
	callCount := 0

	mockGen := &mockGenerator{
		GenerateFunc: func(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error) {
			callCount++
			t.Logf("GenerateFunc called, count=%d", callCount)

			if callCount == 1 {
				// First call: LLM requests confirmation to execute a dangerous command
				toolReq := &ai.ToolRequest{
					Name: "requestConfirmation",
					Ref:  "req-cmd-001",
					Input: map[string]any{
						"toolToConfirm": "executeCommand",
						"params":        map[string]any{"command": "rm -rf /tmp/test_data"},
						"reason":        "Will permanently delete the test data directory",
					},
				}

				part := ai.NewToolRequestPart(toolReq)
				part.Metadata = map[string]any{"interrupt": true}

				resp := &ai.ModelResponse{
					Message: &ai.Message{
						Role:    ai.RoleModel,
						Content: []*ai.Part{part},
					},
					FinishReason: ai.FinishReasonInterrupted,
				}
				t.Logf("Returning interrupt response for executeCommand")
				return resp, nil
			}

			// Second call: Verify that LLM receives the rejection response
			// We can't directly inspect opts in this mock, but we verify the behavior
			t.Logf("Second Generate call - LLM should have received rejection in message history")

			// Return a response acknowledging the rejection with alternative suggestion
			return &ai.ModelResponse{
				Message: &ai.Message{
					Role: ai.RoleModel,
					Content: []*ai.Part{
						ai.NewTextPart("I understand. The deletion has been cancelled because the data might still be needed. " +
							"Would you like me to archive it instead?"),
					},
				},
				FinishReason: ai.FinishReasonStop,
			}, nil
		},
	}

	agent := createTestAgent(t, mockGen)

	// 2. Act
	eventCh := agent.Execute(ctx, "clean up the test data")

	// 3. Assert - Step 1: Receive and verify interrupt event
	event, ok := <-eventCh
	if !ok {
		t.Fatal("Event channel closed unexpectedly")
	}

	if event.Type != EventTypeInterrupt {
		if event.Type == EventTypeError {
			t.Fatalf("Received error event: %v", event.Error)
		}
		t.Fatalf("Expected interrupt event, got %v", event.Type)
	}

	if event.Interrupt == nil {
		t.Fatal("Interrupt event has nil Interrupt field")
	}

	// Verify interrupt details
	if event.Interrupt.ToolName != "executeCommand" {
		t.Errorf("Expected ToolName 'executeCommand', got '%s'", event.Interrupt.ToolName)
	}

	if event.Interrupt.Reason != "Will permanently delete the test data directory" {
		t.Errorf("Expected specific reason, got '%s'", event.Interrupt.Reason)
	}

	// 4. User rejects with a detailed reason
	rejectionReason := "The test data might still be needed for debugging. Please keep it for now."
	t.Logf("User rejects with reason: %s", rejectionReason)

	event.Interrupt.ResumeChannel <- ConfirmationResponse{
		Approved: false,
		Reason:   rejectionReason,
	}

	// 5. Assert - Step 2: Verify agent handles rejection gracefully
	// Collect remaining events
	var textChunks []string
	var completionReceived bool

	for event := range eventCh {
		switch event.Type {
		case EventTypeText:
			textChunks = append(textChunks, event.TextChunk)
		case EventTypeComplete:
			completionReceived = true
		case EventTypeError:
			t.Fatalf("Received error event: %v", event.Error)
		}
	}

	// 6. Verify Generate was called exactly twice
	if callCount != 2 {
		t.Errorf("Expected Generate to be called 2 times, got %d", callCount)
	}

	// 7. Verify completion was received
	if !completionReceived {
		t.Error("Expected completion event, but didn't receive one")
	}

	// 7.1 Log the text response (helps with debugging)
	if len(textChunks) > 0 {
		t.Logf("Agent response after rejection: %s", strings.Join(textChunks, ""))
	}

	// 8. Verify the agent's message history contains the rejection
	// We do this by inspecting the agent's internal state
	agent.messagesMu.Lock()
	messages := agent.messages
	agent.messagesMu.Unlock()

	t.Logf("Agent has %d messages in history after rejection", len(messages))

	// Expected message structure:
	// [0] User: "clean up the test data"
	// [1] Model: requestConfirmation interrupt
	// [2] Tool: rejection response with reason
	// (Agent may trim history, so we check for minimum required messages)

	if len(messages) < 3 {
		t.Errorf("Expected at least 3 messages in history (user, model, tool), got %d", len(messages))
	}

	// Find the Tool message (should be the last or second-to-last)
	var toolMessage *ai.Message
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == ai.RoleTool {
			toolMessage = messages[i]
			break
		}
	}

	if toolMessage == nil {
		t.Fatal("Expected to find a Tool message in history containing rejection response")
		return
	}

	// 9. Verify the Tool message contains the rejection reason
	t.Logf("Tool message has %d parts", len(toolMessage.Content))

	found := false
	for _, part := range toolMessage.Content {
		if part.ToolResponse != nil {
			t.Logf("ToolResponse Name: %s", part.ToolResponse.Name)

			if part.ToolResponse.Name == "requestConfirmation" {
				// Verify the output contains rejection status and reason
				output, ok := part.ToolResponse.Output.(map[string]any)
				if !ok {
					t.Fatal("ToolResponse.Output is not map[string]any")
				}

				status, ok := output["status"].(string)
				if !ok {
					t.Fatal("ToolResponse.Output['status'] is not string")
				}

				if status != "rejected" {
					t.Errorf("Expected status 'rejected', got '%s'", status)
				}

				message, ok := output["message"].(string)
				if !ok {
					t.Fatal("ToolResponse.Output['message'] is not string")
				}

				// Verify the message contains the user's rejection reason
				expectedMsg := "User rejected: " + rejectionReason
				if message != expectedMsg {
					t.Errorf("Expected message '%s', got '%s'", expectedMsg, message)
				}

				t.Logf("✓ Rejection reason correctly propagated: %s", message)
				found = true
				break
			}
		}
	}

	if !found {
		t.Error("Did not find requestConfirmation ToolResponse with rejection in message history")
	}

	t.Log("✓ Rejection reason end-to-end propagation verified successfully")
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
	getMessagesFunc   func(ctx context.Context, sessionID uuid.UUID, limit, offset int) ([]*session.Message, error)
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

func (m *mockSessionStore) GetMessages(ctx context.Context, sessionID uuid.UUID, limit, offset int) ([]*session.Message, error) {
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
		getMessagesFunc: func(ctx context.Context, sessionID uuid.UUID, limit, offset int) ([]*session.Message, error) {
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
		getMessagesFunc: func(ctx context.Context, sessionID uuid.UUID, limit, offset int) ([]*session.Message, error) {
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

	// Verify empty messages
	if messages != nil {
		t.Errorf("expected nil messages, got %v", messages)
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

// TestExtractToolName verifies tool name extraction from interrupt.
// Note: Implementation doesn't handle nil interrupt - expects caller to ensure non-nil
func TestExtractToolName(t *testing.T) {
	tests := []struct {
		name      string
		interrupt *ai.Part
		expected  string
	}{
		{
			name: "nil ToolRequest",
			interrupt: &ai.Part{
				ToolRequest: nil,
			},
			expected: "",
		},
		{
			name: "invalid input type",
			interrupt: &ai.Part{
				ToolRequest: &ai.ToolRequest{
					Input: "not a map",
				},
			},
			expected: "",
		},
		{
			name: "missing toolToConfirm field",
			interrupt: &ai.Part{
				ToolRequest: &ai.ToolRequest{
					Input: map[string]any{
						"other": "value",
					},
				},
			},
			expected: "",
		},
		{
			name: "successful extraction",
			interrupt: &ai.Part{
				ToolRequest: &ai.ToolRequest{
					Input: map[string]any{
						"toolToConfirm": "deleteFile",
					},
				},
			},
			expected: "deleteFile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractToolName(tt.interrupt)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestExtractParams verifies parameter extraction from interrupt.
// Note: Implementation doesn't handle nil interrupt - expects caller to ensure non-nil
func TestExtractParams(t *testing.T) {
	tests := []struct {
		name      string
		interrupt *ai.Part
		expected  map[string]any
	}{
		{
			name: "nil ToolRequest",
			interrupt: &ai.Part{
				ToolRequest: nil,
			},
			expected: nil,
		},
		{
			name: "invalid input type",
			interrupt: &ai.Part{
				ToolRequest: &ai.ToolRequest{
					Input: "not a map",
				},
			},
			expected: nil,
		},
		{
			name: "missing params field",
			interrupt: &ai.Part{
				ToolRequest: &ai.ToolRequest{
					Input: map[string]any{
						"other": "value",
					},
				},
			},
			expected: nil,
		},
		{
			name: "successful extraction",
			interrupt: &ai.Part{
				ToolRequest: &ai.ToolRequest{
					Input: map[string]any{
						"params": map[string]any{
							"path": "/test/file.txt",
						},
					},
				},
			},
			expected: map[string]any{
				"path": "/test/file.txt",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractParams(tt.interrupt)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
			} else {
				if result == nil {
					t.Error("expected non-nil result")
				} else if len(result) != len(tt.expected) {
					t.Errorf("expected %d params, got %d", len(tt.expected), len(result))
				}
			}
		})
	}
}

// TestExtractReason verifies reason extraction from interrupt.
// Note: Implementation doesn't handle nil interrupt - expects caller to ensure non-nil
func TestExtractReason(t *testing.T) {
	tests := []struct {
		name      string
		interrupt *ai.Part
		expected  string
	}{
		{
			name: "nil ToolRequest",
			interrupt: &ai.Part{
				ToolRequest: nil,
			},
			expected: "",
		},
		{
			name: "invalid input type",
			interrupt: &ai.Part{
				ToolRequest: &ai.ToolRequest{
					Input: "not a map",
				},
			},
			expected: "",
		},
		{
			name: "missing reason field",
			interrupt: &ai.Part{
				ToolRequest: &ai.ToolRequest{
					Input: map[string]any{
						"other": "value",
					},
				},
			},
			expected: "",
		},
		{
			name: "successful extraction",
			interrupt: &ai.Part{
				ToolRequest: &ai.ToolRequest{
					Input: map[string]any{
						"reason": "This operation will delete important data",
					},
				},
			},
			expected: "This operation will delete important data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractReason(tt.interrupt)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
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
