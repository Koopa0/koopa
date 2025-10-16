package agent

import (
	"context"
	"fmt"
	"math"
	"sync"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
)

// VectorDocument 向量化的文檔
type VectorDocument struct {
	Content   string    `json:"content"`
	Embedding []float32 `json:"embedding"`
	Metadata  map[string]any `json:"metadata"`
}

// SimpleVectorStore 簡單的記憶體向量存儲（用於演示）
type SimpleVectorStore struct {
	mu        sync.RWMutex
	documents []*VectorDocument
	embedder  ai.Embedder
}

// NewSimpleVectorStore 創建新的簡單向量存儲
func NewSimpleVectorStore(embedder ai.Embedder) *SimpleVectorStore {
	return &SimpleVectorStore{
		documents: make([]*VectorDocument, 0),
		embedder:  embedder,
	}
}

// AddDocument 添加文檔到向量存儲
func (s *SimpleVectorStore) AddDocument(ctx context.Context, content string, metadata map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 生成 embedding
	req := &ai.EmbedRequest{
		Input: []*ai.Document{
			ai.DocumentFromText(content, metadata),
		},
	}

	resp, err := s.embedder.Embed(ctx, req)
	if err != nil {
		return fmt.Errorf("無法生成 embedding: %w", err)
	}

	if len(resp.Embeddings) == 0 {
		return fmt.Errorf("embedding 結果為空")
	}

	// 添加到存儲
	s.documents = append(s.documents, &VectorDocument{
		Content:   content,
		Embedding: resp.Embeddings[0].Embedding,
		Metadata:  metadata,
	})

	return nil
}

// Search 搜尋最相似的文檔
func (s *SimpleVectorStore) Search(ctx context.Context, query string, topK int) ([]*ai.Document, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.documents) == 0 {
		return nil, fmt.Errorf("向量存儲為空")
	}

	// 生成查詢的 embedding
	req := &ai.EmbedRequest{
		Input: []*ai.Document{
			ai.DocumentFromText(query, nil),
		},
	}

	resp, err := s.embedder.Embed(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("無法生成查詢 embedding: %w", err)
	}

	if len(resp.Embeddings) == 0 {
		return nil, fmt.Errorf("查詢 embedding 結果為空")
	}

	queryEmbedding := resp.Embeddings[0].Embedding

	// 計算相似度並排序
	type docWithScore struct {
		doc   *VectorDocument
		score float64
	}

	scored := make([]docWithScore, len(s.documents))
	for i, doc := range s.documents {
		similarity := cosineSimilarity(queryEmbedding, doc.Embedding)
		scored[i] = docWithScore{doc: doc, score: similarity}
	}

	// 簡單的排序（按相似度降序）
	for i := 0; i < len(scored)-1; i++ {
		for j := i + 1; j < len(scored); j++ {
			if scored[j].score > scored[i].score {
				scored[i], scored[j] = scored[j], scored[i]
			}
		}
	}

	// 取前 topK 個結果
	if topK > len(scored) {
		topK = len(scored)
	}

	results := make([]*ai.Document, topK)
	for i := 0; i < topK; i++ {
		results[i] = ai.DocumentFromText(scored[i].doc.Content, scored[i].doc.Metadata)
	}

	return results, nil
}

// Clear 清空向量存儲
func (s *SimpleVectorStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.documents = make([]*VectorDocument, 0)
}

// Size 返回存儲的文檔數量
func (s *SimpleVectorStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.documents)
}

// cosineSimilarity 計算餘弦相似度
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

// RAGManager RAG 管理器
type RAGManager struct {
	vectorStore *SimpleVectorStore
	embedder    ai.Embedder
}

// NewRAGManager 創建新的 RAG 管理器
func NewRAGManager(ctx context.Context, g *genkit.Genkit) (*RAGManager, error) {
	// 使用 Google AI 的 text-embedding-004 模型
	embedder := googlegenai.VertexAIEmbedder(g, "text-embedding-004")

	vectorStore := NewSimpleVectorStore(embedder)

	return &RAGManager{
		vectorStore: vectorStore,
		embedder:    embedder,
	}, nil
}

// IndexText 索引文本
func (r *RAGManager) IndexText(ctx context.Context, text string, metadata map[string]any) error {
	return r.vectorStore.AddDocument(ctx, text, metadata)
}

// IndexTexts 批量索引文本
func (r *RAGManager) IndexTexts(ctx context.Context, texts []string) error {
	for i, text := range texts {
		metadata := map[string]any{
			"index": i,
		}
		if err := r.vectorStore.AddDocument(ctx, text, metadata); err != nil {
			return fmt.Errorf("索引第 %d 個文本失敗: %w", i, err)
		}
	}
	return nil
}

// Retrieve 檢索相關文檔
func (r *RAGManager) Retrieve(ctx context.Context, query string, topK int) ([]*ai.Document, error) {
	return r.vectorStore.Search(ctx, query, topK)
}

// GetVectorStore 獲取向量存儲
func (r *RAGManager) GetVectorStore() *SimpleVectorStore {
	return r.vectorStore
}

// DefineRetriever 定義一個 Genkit Retriever
func (r *RAGManager) DefineRetriever(g *genkit.Genkit, name string) ai.Retriever {
	return genkit.DefineRetriever(
		g, name, nil,
		func(ctx context.Context, req *ai.RetrieverRequest) (*ai.RetrieverResponse, error) {
			// 從 query 中提取文本
			queryText := ""
			if req.Query != nil && len(req.Query.Content) > 0 {
				queryText = req.Query.Content[0].Text
			}

			// 默認返回前 3 個結果
			topK := 3
			if opts, ok := req.Options.(map[string]any); ok {
				if k, exists := opts["k"]; exists {
					if kInt, ok := k.(int); ok {
						topK = kInt
					}
				}
			}

			// 檢索文檔
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
