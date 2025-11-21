package agent

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/sqlc"
)

// ============================================================================
// Conversation History and Vectorization Tests
// ============================================================================
// Tests in this file cover history-related Agent functionality:
//   - Message text extraction
//   - Tool information extraction
//   - Turn content building for vectorization
//   - Session ID management for vectorization
//   - Conversation turn vectorization with retry logic
//   - Turn number calculation
//
// These tests verify that conversation history is properly processed,
// formatted, and vectorized for RAG functionality.
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
				sessionStore:     &mockSessionStore{},
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

// ============================================================================
// Helper Mocks and Functions
// ============================================================================

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
