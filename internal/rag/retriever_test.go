package rag

import (
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa/internal/knowledge"
)

// TestNew removed - it was testing constructor with mock interface
// Since we removed VectorStore interface, this test is no longer needed
// Integration tests with real PostgreSQL should be used instead (via testcontainers)

func TestExtractQueryText(t *testing.T) {
	tests := []struct {
		name     string
		req      *ai.RetrieverRequest
		expected string
	}{
		{
			name: "valid query with text",
			req: &ai.RetrieverRequest{
				Query: &ai.Document{
					Content: []*ai.Part{
						ai.NewTextPart("test query"),
					},
				},
			},
			expected: "test query",
		},
		{
			name: "nil query",
			req: &ai.RetrieverRequest{
				Query: nil,
			},
			expected: "",
		},
		{
			name: "empty content",
			req: &ai.RetrieverRequest{
				Query: &ai.Document{
					Content: []*ai.Part{},
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractQueryText(tt.req)
			if result != tt.expected {
				t.Errorf("extractQueryText() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestExtractTopK(t *testing.T) {
	tests := []struct {
		name     string
		req      *ai.RetrieverRequest
		defaultK int
		expected int
	}{
		{
			name: "with k option",
			req: &ai.RetrieverRequest{
				Options: map[string]any{
					"k": 10,
				},
			},
			defaultK: 5,
			expected: 10,
		},
		{
			name: "without k option",
			req: &ai.RetrieverRequest{
				Options: map[string]any{},
			},
			defaultK: 5,
			expected: 5,
		},
		{
			name:     "nil options",
			req:      &ai.RetrieverRequest{},
			defaultK: 3,
			expected: 3,
		},
		{
			name: "k is not int",
			req: &ai.RetrieverRequest{
				Options: map[string]any{
					"k": "not an int",
				},
			},
			defaultK: 5,
			expected: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTopK(tt.req, tt.defaultK)
			if result != tt.expected {
				t.Errorf("extractTopK() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestConvertToGenkitDocuments(t *testing.T) {
	results := []knowledge.Result{
		{
			Document: knowledge.Document{
				ID:      "doc1",
				Content: "test content 1",
				Metadata: map[string]string{
					"source_type": "conversation",
					"session_id":  "123",
				},
			},
			Similarity: 0.95,
		},
		{
			Document: knowledge.Document{
				ID:      "doc2",
				Content: "test content 2",
				Metadata: map[string]string{
					"source_type": "notion",
				},
			},
			Similarity: 0.85,
		},
	}

	docs := convertToGenkitDocuments(results)

	if len(docs) != 2 {
		t.Fatalf("expected 2 documents, got %d", len(docs))
	}

	// Check first document
	if docs[0].Content[0].Text != "test content 1" {
		t.Errorf("doc[0] content = %q, want %q", docs[0].Content[0].Text, "test content 1")
	}

	// Check metadata preservation
	if docs[0].Metadata["source_type"] != "conversation" {
		t.Error("metadata not preserved correctly")
	}

	// Check similarity score in metadata
	if similarity, ok := docs[0].Metadata["similarity"].(float32); !ok || similarity != 0.95 {
		t.Errorf("similarity = %v, want 0.95", docs[0].Metadata["similarity"])
	}

	// Check second document
	if docs[1].Content[0].Text != "test content 2" {
		t.Errorf("doc[1] content = %q, want %q", docs[1].Content[0].Text, "test content 2")
	}
}
