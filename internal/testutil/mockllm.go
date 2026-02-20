package testutil

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strings"
	"sync"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// MockLLM provides deterministic LLM responses for testing.
// It matches user message content against registered patterns
// and returns the corresponding response.
//
// Thread-safe for concurrent use.
type MockLLM struct {
	mu        sync.Mutex
	responses []mockRule
	fallback  string
	calls     []MockCall
}

type mockRule struct {
	pattern  string            // substring match in user message
	response string            // text response
	tools    []*ai.ToolRequest // tool calls to request (nil = text only)
}

// MockCall records a single call to the mock model.
type MockCall struct {
	UserMessage string // last user message text
	Response    string // response text returned
}

// NewMockLLM creates a mock LLM with the given fallback response.
// The fallback is returned when no pattern matches.
func NewMockLLM(fallback string) *MockLLM {
	return &MockLLM{fallback: fallback}
}

// AddResponse registers a pattern-response pair.
// When a user message contains the pattern (case-insensitive), the response is returned.
// Patterns are checked in registration order; first match wins.
func (m *MockLLM) AddResponse(pattern, response string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses = append(m.responses, mockRule{
		pattern:  strings.ToLower(pattern),
		response: response,
	})
}

// AddToolResponse registers a pattern that triggers tool calls.
func (m *MockLLM) AddToolResponse(pattern string, tools []*ai.ToolRequest, textResponse string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses = append(m.responses, mockRule{
		pattern:  strings.ToLower(pattern),
		response: textResponse,
		tools:    tools,
	})
}

// Calls returns a copy of all recorded calls.
func (m *MockLLM) Calls() []MockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]MockCall, len(m.calls))
	copy(cp, m.calls)
	return cp
}

// Reset clears all recorded calls (keeps registered responses).
func (m *MockLLM) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = nil
}

// RegisterModel registers the mock as a Genkit model and returns a reference.
// The model name will be "mock/test-model".
func (m *MockLLM) RegisterModel(g *genkit.Genkit) ai.Model {
	return genkit.DefineModel(g, "mock/test-model", &ai.ModelOptions{
		Label: "Mock Test Model",
		Supports: &ai.ModelSupports{
			Multiturn:  true,
			Tools:      true,
			SystemRole: true,
			Media:      false,
		},
	}, m.generate)
}

// generate is the Genkit model function.
func (m *MockLLM) generate(ctx context.Context, req *ai.ModelRequest, cb ai.ModelStreamCallback) (*ai.ModelResponse, error) {
	// Extract last user message
	var userText string
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == ai.RoleUser {
			userText = req.Messages[i].Text()
			break
		}
	}

	// Find matching rule
	m.mu.Lock()
	var matched *mockRule
	lower := strings.ToLower(userText)
	for i := range m.responses {
		if strings.Contains(lower, m.responses[i].pattern) {
			matched = &m.responses[i]
			break
		}
	}

	responseText := m.fallback
	if matched != nil {
		responseText = matched.response
	}

	m.calls = append(m.calls, MockCall{
		UserMessage: userText,
		Response:    responseText,
	})
	m.mu.Unlock()

	// Stream if callback provided
	if cb != nil {
		_ = cb(ctx, &ai.ModelResponseChunk{
			Content: []*ai.Part{ai.NewTextPart(responseText)},
		})
	}

	// Build response parts
	var parts []*ai.Part
	if matched != nil && len(matched.tools) > 0 {
		for _, tr := range matched.tools {
			parts = append(parts, &ai.Part{
				Kind:        ai.PartToolRequest,
				ToolRequest: tr,
			})
		}
	}
	parts = append(parts, ai.NewTextPart(responseText))

	return &ai.ModelResponse{
		Request: req,
		Message: &ai.Message{
			Role:    ai.RoleModel,
			Content: parts,
		},
	}, nil
}

// MockEmbedder provides deterministic embedding vectors for testing.
//
// By default, it generates a deterministic vector from content using SHA-256.
// Explicit mappings can be added for precise cosine similarity control.
//
// Thread-safe for concurrent use.
type MockEmbedder struct {
	mu      sync.Mutex
	vectors map[string][]float32
	dim     int
}

// NewMockEmbedder creates a mock embedder with the given vector dimensions.
func NewMockEmbedder(dim int) *MockEmbedder {
	return &MockEmbedder{
		vectors: make(map[string][]float32),
		dim:     dim,
	}
}

// SetVector registers an explicit vector for a given content string.
// Use this to control exact cosine similarity between test inputs.
func (e *MockEmbedder) SetVector(content string, vec []float32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.vectors[content] = vec
}

// RegisterEmbedder registers the mock as a Genkit embedder.
// The embedder name will be "mock/test-embedder".
func (e *MockEmbedder) RegisterEmbedder(g *genkit.Genkit) ai.Embedder {
	return genkit.DefineEmbedder(g, "mock/test-embedder", &ai.EmbedderOptions{
		Label:      "Mock Test Embedder",
		Dimensions: e.dim,
	}, e.embed)
}

// embed is the Genkit embedder function.
func (e *MockEmbedder) embed(_ context.Context, req *ai.EmbedRequest) (*ai.EmbedResponse, error) {
	embeddings := make([]*ai.Embedding, len(req.Input))
	for i, doc := range req.Input {
		text := documentText(doc)
		embeddings[i] = &ai.Embedding{
			Embedding: e.vectorFor(text),
		}
	}
	return &ai.EmbedResponse{Embeddings: embeddings}, nil
}

// vectorFor returns the vector for a given content string.
// Uses explicit mapping if available, otherwise generates deterministically from hash.
func (e *MockEmbedder) vectorFor(content string) []float32 {
	e.mu.Lock()
	if v, ok := e.vectors[content]; ok {
		e.mu.Unlock()
		return v
	}
	e.mu.Unlock()

	return deterministicVector(content, e.dim)
}

// documentText extracts all text content from a Document's parts.
func documentText(doc *ai.Document) string {
	var sb strings.Builder
	for _, p := range doc.Content {
		if p.Kind == ai.PartText {
			sb.WriteString(p.Text)
		}
	}
	return sb.String()
}

// deterministicVector generates a normalized vector from content using SHA-256.
// The same content always produces the same vector.
func deterministicVector(content string, dim int) []float32 {
	hash := sha256.Sum256([]byte(content))
	vec := make([]float32, dim)

	// Use hash bytes to seed vector values
	for i := range vec {
		// Cycle through hash bytes
		idx := (i * 4) % len(hash)
		bits := binary.LittleEndian.Uint32([]byte{
			hash[idx%32],
			hash[(idx+1)%32],
			hash[(idx+2)%32],
			hash[(idx+3)%32],
		})
		// Map to [-1, 1] range
		vec[i] = (float32(bits)/float32(math.MaxUint32))*2 - 1
	}

	// Normalize to unit vector
	var norm float32
	for _, v := range vec {
		norm += v * v
	}
	norm = float32(math.Sqrt(float64(norm)))
	if norm > 0 {
		for i := range vec {
			vec[i] /= norm
		}
	}

	return vec
}
