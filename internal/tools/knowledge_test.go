package tools

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core/api"
	"github.com/firebase/genkit/go/plugins/postgresql"
)

// mockRetriever is a minimal ai.Retriever implementation for testing.
type mockRetriever struct{}

func (*mockRetriever) Name() string { return "mock-retriever" }
func (*mockRetriever) Retrieve(_ context.Context, _ *ai.RetrieverRequest) (*ai.RetrieverResponse, error) {
	return &ai.RetrieverResponse{}, nil
}
func (*mockRetriever) Register(_ api.Registry) {}

func TestClampTopK(t *testing.T) {
	tests := []struct {
		name       string
		topK       int
		defaultVal int
		want       int
	}{
		{name: "zero uses default", topK: 0, defaultVal: 3, want: 3},
		{name: "negative uses default", topK: -5, defaultVal: 5, want: 5},
		{name: "value in range unchanged", topK: 5, defaultVal: 3, want: 5},
		{name: "max boundary", topK: 10, defaultVal: 3, want: 10},
		{name: "exceeds max clamped to 10", topK: 50, defaultVal: 3, want: 10},
		{name: "min value", topK: 1, defaultVal: 3, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clampTopK(tt.topK, tt.defaultVal)
			if got != tt.want {
				t.Errorf("clampTopK(%d, %d) = %d, want %d", tt.topK, tt.defaultVal, got, tt.want)
			}
		})
	}
}

func TestKnowledgeToolConstants(t *testing.T) {
	if SearchHistoryName != "search_history" {
		t.Errorf("SearchHistoryName = %q, want %q", SearchHistoryName, "search_history")
	}
	if SearchDocumentsName != "search_documents" {
		t.Errorf("SearchDocumentsName = %q, want %q", SearchDocumentsName, "search_documents")
	}
	if SearchSystemKnowledgeName != "search_system_knowledge" {
		t.Errorf("SearchSystemKnowledgeName = %q, want %q", SearchSystemKnowledgeName, "search_system_knowledge")
	}
	if StoreKnowledgeName != "knowledge_store" {
		t.Errorf("StoreKnowledgeName = %q, want %q", StoreKnowledgeName, "knowledge_store")
	}
}

func TestNewKnowledge(t *testing.T) {
	t.Run("nil retriever returns error", func(t *testing.T) {
		if _, err := NewKnowledge(nil, nil, slog.New(slog.DiscardHandler)); err == nil {
			t.Error("NewKnowledge(nil, nil, logger) error = nil, want non-nil")
		}
	})

	t.Run("nil logger returns error", func(t *testing.T) {
		if _, err := NewKnowledge(&mockRetriever{}, nil, nil); err == nil {
			t.Error("NewKnowledge(retriever, nil, nil) error = nil, want non-nil")
		}
	})
}

func TestKnowledgeDefaultTopKConstants(t *testing.T) {
	if DefaultHistoryTopK != 3 {
		t.Errorf("DefaultHistoryTopK = %d, want 3", DefaultHistoryTopK)
	}
	if DefaultDocumentsTopK != 5 {
		t.Errorf("DefaultDocumentsTopK = %d, want 5", DefaultDocumentsTopK)
	}
	if DefaultSystemKnowledgeTopK != 3 {
		t.Errorf("DefaultSystemKnowledgeTopK = %d, want 3", DefaultSystemKnowledgeTopK)
	}
	if MaxTopK != 10 {
		t.Errorf("MaxTopK = %d, want 10", MaxTopK)
	}
}

func TestValidSourceTypes(t *testing.T) {
	// Verify all expected source types are valid
	validTypes := []string{"conversation", "file", "system"}
	for _, st := range validTypes {
		if !validSourceTypes[st] {
			t.Errorf("validSourceTypes[%q] = false, want true", st)
		}
	}

	// Verify SQL injection attempts are rejected
	invalidTypes := []string{
		"'; DROP TABLE documents; --",
		"conversation' OR '1'='1",
		"file\x00injection",
		"unknown",
		"",
	}
	for _, st := range invalidTypes {
		if validSourceTypes[st] {
			t.Errorf("validSourceTypes[%q] = true, want false (SQL injection risk)", st)
		}
	}
}

func TestStoreKnowledge_Validation(t *testing.T) {
	// knowledgeWithDocStore creates a Knowledge instance with a non-nil docStore
	// for testing validation paths. The zero-value DocStore is safe because
	// all test cases trigger validation errors before docStore.Index is called.
	knowledgeWithDocStore := &Knowledge{
		retriever: &mockRetriever{},
		docStore:  &postgresql.DocStore{},
		logger:    slog.New(slog.DiscardHandler),
	}

	knowledgeNilDocStore, err := NewKnowledge(&mockRetriever{}, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewKnowledge() unexpected error: %v", err)
	}

	tests := []struct {
		name      string
		kt        *Knowledge
		input     KnowledgeStoreInput
		wantCode  ErrorCode
		wantInMsg string
	}{
		{
			name:      "nil docStore returns not available",
			kt:        knowledgeNilDocStore,
			input:     KnowledgeStoreInput{Title: "t", Content: "c"},
			wantCode:  ErrCodeExecution,
			wantInMsg: "not available",
		},
		{
			name:      "empty title",
			kt:        knowledgeWithDocStore,
			input:     KnowledgeStoreInput{Title: "", Content: "c"},
			wantCode:  ErrCodeValidation,
			wantInMsg: "title is required",
		},
		{
			name:      "empty content",
			kt:        knowledgeWithDocStore,
			input:     KnowledgeStoreInput{Title: "t", Content: ""},
			wantCode:  ErrCodeValidation,
			wantInMsg: "content is required",
		},
		{
			name: "content exceeds maximum size",
			kt:   knowledgeWithDocStore,
			input: KnowledgeStoreInput{
				Title:   "large doc",
				Content: strings.Repeat("x", MaxKnowledgeContentSize+1),
			},
			wantCode:  ErrCodeValidation,
			wantInMsg: "exceeds maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.kt.StoreKnowledge(nil, tt.input)
			if err != nil {
				t.Fatalf("StoreKnowledge() unexpected error: %v", err)
			}
			if result.Status != StatusError {
				t.Fatalf("StoreKnowledge() status = %q, want %q", result.Status, StatusError)
			}
			if result.Error == nil {
				t.Fatal("StoreKnowledge() error field is nil, want non-nil")
			}
			if result.Error.Code != tt.wantCode {
				t.Errorf("StoreKnowledge() error code = %q, want %q", result.Error.Code, tt.wantCode)
			}
			if !strings.Contains(result.Error.Message, tt.wantInMsg) {
				t.Errorf("StoreKnowledge() error message = %q, want to contain %q", result.Error.Message, tt.wantInMsg)
			}
		})
	}
}
