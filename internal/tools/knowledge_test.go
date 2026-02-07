package tools

import (
	"context"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core/api"
	"github.com/koopa0/koopa/internal/log"
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
		{"zero uses default", 0, 3, 3},
		{"negative uses default", -5, 5, 5},
		{"value in range unchanged", 5, 3, 5},
		{"max boundary", 10, 3, 10},
		{"exceeds max clamped to 10", 50, 3, 10},
		{"min value", 1, 3, 1},
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
	if ToolSearchHistory != "search_history" {
		t.Errorf("ToolSearchHistory = %q, want %q", ToolSearchHistory, "search_history")
	}
	if ToolSearchDocuments != "search_documents" {
		t.Errorf("ToolSearchDocuments = %q, want %q", ToolSearchDocuments, "search_documents")
	}
	if ToolSearchSystemKnowledge != "search_system_knowledge" {
		t.Errorf("ToolSearchSystemKnowledge = %q, want %q", ToolSearchSystemKnowledge, "search_system_knowledge")
	}
	if ToolStoreKnowledge != "knowledge_store" {
		t.Errorf("ToolStoreKnowledge = %q, want %q", ToolStoreKnowledge, "knowledge_store")
	}
}

func TestNewKnowledgeTools(t *testing.T) {
	t.Run("nil retriever returns error", func(t *testing.T) {
		if _, err := NewKnowledgeTools(nil, nil, log.NewNop()); err == nil {
			t.Error("expected error for nil retriever")
		}
	})

	t.Run("nil logger returns error", func(t *testing.T) {
		if _, err := NewKnowledgeTools(&mockRetriever{}, nil, nil); err == nil {
			t.Error("expected error for nil logger")
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
			t.Errorf("expected %q to be valid source type", st)
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
			t.Errorf("expected %q to be invalid source type (SQL injection risk)", st)
		}
	}
}
