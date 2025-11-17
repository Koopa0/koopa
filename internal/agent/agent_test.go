package agent

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core/api"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/config"
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

	agent, err := New(ctx, cfg, g, &mockRetriever{}, NewNoopSessionStore(), slog.Default())
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
