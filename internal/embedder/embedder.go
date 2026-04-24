// Package embedder generates vector embeddings for knowledge content.
//
// Backed by Google's gemini-embedding-2-preview model at 1536 dimensions
// (Matryoshka-truncated from the model's native 3072d). Callers treat the
// Embedder as an opaque dependency — no interface is exported because there
// is exactly one implementation today. If a second provider surfaces, the
// interface is discovered from usage, not designed up front.
package embedder

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/genai"
)

// Model and dimension are server-wide constants. If the model or its
// Matryoshka-truncation point ever changes, every persisted embedding is
// incompatible with the new one — a schema migration and full re-embed
// is required before flipping either of these values.
const (
	Model     = "gemini-embedding-2-preview"
	Dimension = 1536
)

// ErrEmptyInput is returned when Embed is called with an empty string.
// The Gemini API rejects empty input; catching it locally avoids a
// network round-trip for a known-invalid request.
var ErrEmptyInput = errors.New("embedder: empty input")

// Embedder produces 1536-dim vector embeddings via the Gemini Gen AI SDK.
// Safe for concurrent use — the underlying *genai.Client is goroutine-safe.
type Embedder struct {
	client *genai.Client
	dim    int32
}

// New constructs an Embedder for the Gemini API. An empty apiKey is a
// configuration error — returning a nil Embedder forces the caller to
// decide whether to fail startup or skip embedding for this run.
func New(ctx context.Context, apiKey string) (*Embedder, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("embedder: apiKey is required")
	}
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return nil, fmt.Errorf("embedder: creating genai client: %w", err)
	}
	return &Embedder{
		client: client,
		dim:    int32(Dimension),
	}, nil
}

// Embed returns a Matryoshka-truncated 1536-dim embedding for text. The
// caller must supply a bounded context — a slow or hung Gemini response
// blocks the embed call, and the calling handler almost always has its own
// upper deadline. TaskType is fixed at RETRIEVAL_DOCUMENT because every
// persisted embedding in koopa is a "document" to be retrieved later;
// query-time embeddings use EmbedQuery.
func (e *Embedder) Embed(ctx context.Context, text string) ([]float32, error) {
	return e.embed(ctx, text, "RETRIEVAL_DOCUMENT")
}

// EmbedQuery returns a 1536-dim embedding for a search query. Uses
// TaskType=RETRIEVAL_QUERY, which Gemini optimizes to match against
// embeddings produced under RETRIEVAL_DOCUMENT — the two task types are
// the complementary pair in Gemini's embedding API. Interactive callers
// should bound ctx aggressively (the MCP search_knowledge handler applies
// a sub-second deadline).
func (e *Embedder) EmbedQuery(ctx context.Context, query string) ([]float32, error) {
	return e.embed(ctx, query, "RETRIEVAL_QUERY")
}

func (e *Embedder) embed(ctx context.Context, text, taskType string) ([]float32, error) {
	if text == "" {
		return nil, ErrEmptyInput
	}
	dim := e.dim
	resp, err := e.client.Models.EmbedContent(
		ctx,
		Model,
		[]*genai.Content{genai.NewContentFromText(text, genai.RoleUser)},
		&genai.EmbedContentConfig{
			TaskType:             taskType,
			OutputDimensionality: &dim,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("embedder: embedding content: %w", err)
	}
	if len(resp.Embeddings) == 0 || resp.Embeddings[0] == nil {
		return nil, fmt.Errorf("embedder: no embeddings returned")
	}
	values := resp.Embeddings[0].Values
	if len(values) != Dimension {
		return nil, fmt.Errorf("embedder: expected %d-dim embedding, got %d", Dimension, len(values))
	}
	return values, nil
}
