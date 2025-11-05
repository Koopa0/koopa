package knowledge

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	chromem "github.com/philippgille/chromem-go"
)

// NewEmbeddingFunc creates a chromem-go EmbeddingFunc from a Genkit ai.Embedder.
// The returned function bridges Genkit's embedding API with chromem-go's requirements.
//
// Note: chromem-go automatically normalizes vectors, so no manual normalization is needed.
func NewEmbeddingFunc(embedder ai.Embedder) chromem.EmbeddingFunc {
	return func(ctx context.Context, text string) ([]float32, error) {
		req := &ai.EmbedRequest{
			Input: []*ai.Document{
				ai.DocumentFromText(text, nil),
			},
		}

		resp, err := embedder.Embed(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("embed failed: %w", err)
		}

		if len(resp.Embeddings) == 0 {
			return nil, fmt.Errorf("no embeddings returned")
		}

		return resp.Embeddings[0].Embedding, nil
	}
}
