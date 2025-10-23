package agent

import (
	"container/heap"
	"context"
	"fmt"
	"math"
	"sync"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
)

// VectorDocument vectorized document
type VectorDocument struct {
	Content   string    `json:"content"`
	Embedding []float32 `json:"embedding"`
	Metadata  map[string]any `json:"metadata"`
}

// docWithScore document and score structure for sorting
type docWithScore struct {
	doc   *VectorDocument
	score float64
}

// minHeap implements a min-heap for efficient Top-K retrieval
type minHeap []docWithScore

func (h minHeap) Len() int           { return len(h) }
func (h minHeap) Less(i, j int) bool { return h[i].score < h[j].score }
func (h minHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *minHeap) Push(x interface{}) {
	*h = append(*h, x.(docWithScore))
}

func (h *minHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// SimpleVectorStore simple in-memory vector store
//
// Note: This is a demonstration-only in-memory implementation and is not suitable for production use.
// In production environments, please use Genkit plugins for dedicated vector databases
// (such as ChromaDB, Pinecone, Weaviate, etc.) to achieve high-performance and scalable vector retrieval.
type SimpleVectorStore struct {
	mu        sync.RWMutex
	documents []*VectorDocument
	embedder  ai.Embedder
}

// NewSimpleVectorStore creates a new simple vector store
func NewSimpleVectorStore(embedder ai.Embedder) *SimpleVectorStore {
	return &SimpleVectorStore{
		documents: make([]*VectorDocument, 0),
		embedder:  embedder,
	}
}

// AddDocument adds a document to the vector store
func (s *SimpleVectorStore) AddDocument(ctx context.Context, content string, metadata map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate embedding
	req := &ai.EmbedRequest{
		Input: []*ai.Document{
			ai.DocumentFromText(content, metadata),
		},
	}

	resp, err := s.embedder.Embed(ctx, req)
	if err != nil {
		return fmt.Errorf("unable to generate embedding: %w", err)
	}

	if len(resp.Embeddings) == 0 {
		return fmt.Errorf("embedding result is empty")
	}

	// Add to store
	s.documents = append(s.documents, &VectorDocument{
		Content:   content,
		Embedding: resp.Embeddings[0].Embedding,
		Metadata:  metadata,
	})

	return nil
}

// Search searches for the most similar documents
func (s *SimpleVectorStore) Search(ctx context.Context, query string, topK int) ([]*ai.Document, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.documents) == 0 {
		return nil, fmt.Errorf("vector store is empty")
	}

	// Generate query embedding
	req := &ai.EmbedRequest{
		Input: []*ai.Document{
			ai.DocumentFromText(query, nil),
		},
	}

	resp, err := s.embedder.Embed(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("unable to generate query embedding: %w", err)
	}

	if len(resp.Embeddings) == 0 {
		return nil, fmt.Errorf("query embedding result is empty")
	}

	queryEmbedding := resp.Embeddings[0].Embedding

	// Use min-heap to efficiently find Top-K most similar documents
	// Time complexity: O(N log K), where N is total number of documents, K is number of results returned
	h := &minHeap{}
	heap.Init(h)

	for _, doc := range s.documents {
		similarity := cosineSimilarity(queryEmbedding, doc.Embedding)

		if h.Len() < topK {
			// Heap not full, add directly
			heap.Push(h, docWithScore{doc: doc, score: similarity})
		} else if similarity > (*h)[0].score {
			// Current document is more similar than heap top (minimum), replace heap top
			heap.Pop(h)
			heap.Push(h, docWithScore{doc: doc, score: similarity})
		}
	}

	// Extract results from heap and reverse order (from most similar to least similar)
	results := make([]*ai.Document, h.Len())
	for i := h.Len() - 1; i >= 0; i-- {
		item := heap.Pop(h).(docWithScore)
		results[i] = ai.DocumentFromText(item.doc.Content, item.doc.Metadata)
	}

	return results, nil
}

// Clear clears the vector store
func (s *SimpleVectorStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.documents = make([]*VectorDocument, 0)
}

// Size returns the number of stored documents
func (s *SimpleVectorStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.documents)
}

// cosineSimilarity calculates cosine similarity
func cosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) {
		return 0
	}

	var dotProduct, normA, normB float64
	for i := range a {
		dotProduct += float64(a[i] * b[i])
		normA += float64(a[i] * a[i])
		normB += float64(b[i] * b[i])
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}

// RAGManager RAG manager
type RAGManager struct {
	vectorStore *SimpleVectorStore
	embedder    ai.Embedder
}

// NewRAGManager creates a new RAG manager
func NewRAGManager(ctx context.Context, g *genkit.Genkit) (*RAGManager, error) {
	// Use Google AI's text-embedding-004 model
	embedder := googlegenai.VertexAIEmbedder(g, "text-embedding-004")

	vectorStore := NewSimpleVectorStore(embedder)

	return &RAGManager{
		vectorStore: vectorStore,
		embedder:    embedder,
	}, nil
}

// IndexText indexes text
func (r *RAGManager) IndexText(ctx context.Context, text string, metadata map[string]any) error {
	return r.vectorStore.AddDocument(ctx, text, metadata)
}

// IndexTexts indexes multiple texts in batch
func (r *RAGManager) IndexTexts(ctx context.Context, texts []string) error {
	for i, text := range texts {
		metadata := map[string]any{
			"index": i,
		}
		if err := r.vectorStore.AddDocument(ctx, text, metadata); err != nil {
			return fmt.Errorf("failed to index text %d: %w", i, err)
		}
	}
	return nil
}

// Retrieve retrieves relevant documents
func (r *RAGManager) Retrieve(ctx context.Context, query string, topK int) ([]*ai.Document, error) {
	return r.vectorStore.Search(ctx, query, topK)
}

// GetVectorStore retrieves the vector store
func (r *RAGManager) GetVectorStore() *SimpleVectorStore {
	return r.vectorStore
}

// DefineRetriever defines a Genkit Retriever
func (r *RAGManager) DefineRetriever(g *genkit.Genkit, name string) ai.Retriever {
	return genkit.DefineRetriever(
		g, name, nil,
		func(ctx context.Context, req *ai.RetrieverRequest) (*ai.RetrieverResponse, error) {
			// Extract text from query
			queryText := ""
			if req.Query != nil && len(req.Query.Content) > 0 {
				queryText = req.Query.Content[0].Text
			}

			// Default to returning top 3 results
			topK := 3
			if opts, ok := req.Options.(map[string]any); ok {
				if k, exists := opts["k"]; exists {
					if kInt, ok := k.(int); ok {
						topK = kInt
					}
				}
			}

			// Retrieve documents
			docs, err := r.Retrieve(ctx, queryText, topK)
			if err != nil {
				return nil, err
			}

			return &ai.RetrieverResponse{
				Documents: docs,
			}, nil
		},
	)
}
