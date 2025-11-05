package knowledge

import (
	"context"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core/api"
)

// mockEmbedder is a simple mock implementation of ai.Embedder for testing
type mockEmbedder struct{}

func (m *mockEmbedder) Name() string {
	return "mock-embedder"
}

func (m *mockEmbedder) Register(_ api.Registry) {
	// No-op for testing
}

func (m *mockEmbedder) Embed(ctx context.Context, req *ai.EmbedRequest) (*ai.EmbedResponse, error) {
	// Return fixed embeddings for testing
	embeddings := make([]*ai.Embedding, len(req.Input))
	for i := range req.Input {
		// Simple mock: use position-based embeddings
		embedding := make([]float32, 3) // Small dimension for testing
		embedding[0] = float32(i)
		embedding[1] = float32(i + 1)
		embedding[2] = float32(i + 2)
		embeddings[i] = &ai.Embedding{
			Embedding: embedding,
		}
	}
	return &ai.EmbedResponse{
		Embeddings: embeddings,
	}, nil
}

func TestNewEmbeddingFunc(t *testing.T) {
	embedder := &mockEmbedder{}
	embeddingFunc := NewEmbeddingFunc(embedder)

	ctx := context.Background()
	text := "test document"

	// Call the embedding function
	embedding, err := embeddingFunc(ctx, text)
	if err != nil {
		t.Fatalf("NewEmbeddingFunc failed: %v", err)
	}

	// Verify result
	if len(embedding) != 3 {
		t.Errorf("expected embedding dimension 3, got %d", len(embedding))
	}

	// First document should have embedding [0, 1, 2]
	expectedEmbedding := []float32{0, 1, 2}
	for i, val := range expectedEmbedding {
		if embedding[i] != val {
			t.Errorf("embedding[%d] = %f, want %f", i, embedding[i], val)
		}
	}
}

func TestNewEmbeddingFunc_EmptyResult(t *testing.T) {
	// Mock embedder that returns empty result
	embedder := &emptyEmbedder{}
	embeddingFunc := NewEmbeddingFunc(embedder)

	ctx := context.Background()
	_, err := embeddingFunc(ctx, "test")

	if err == nil {
		t.Error("expected error for empty embeddings, got nil")
	}
}

// emptyEmbedder returns empty embeddings
type emptyEmbedder struct{}

func (e *emptyEmbedder) Name() string {
	return "empty-embedder"
}

func (e *emptyEmbedder) Register(_ api.Registry) {
	// No-op for testing
}

func (e *emptyEmbedder) Embed(ctx context.Context, req *ai.EmbedRequest) (*ai.EmbedResponse, error) {
	return &ai.EmbedResponse{
		Embeddings: []*ai.Embedding{}, // Empty
	}, nil
}
