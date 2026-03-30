package content

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	pgvector "github.com/pgvector/pgvector-go"
	"google.golang.org/genai"
)

// Embedder generates embeddings for content records that lack them.
// Mirrors note.Embedder but operates on the contents table (TILs, articles, notes).
type Embedder struct {
	store    *Store
	embedder ai.Embedder
	g        *genkit.Genkit
	logger   *slog.Logger
}

// NewEmbedder returns a content Embedder.
func NewEmbedder(store *Store, embedder ai.Embedder, g *genkit.Genkit, logger *slog.Logger) *Embedder {
	return &Embedder{store: store, embedder: embedder, g: g, logger: logger}
}

// EmbedMissing generates embeddings for up to limit contents without embeddings.
// Returns the number of contents successfully embedded.
func (e *Embedder) EmbedMissing(ctx context.Context, limit int32) (int, error) {
	candidates, err := e.store.ContentsWithoutEmbedding(ctx, limit)
	if err != nil {
		return 0, fmt.Errorf("listing contents without embedding: %w", err)
	}
	if len(candidates) == 0 {
		return 0, nil
	}
	var embedded int
	for _, c := range candidates {
		if err := e.embedOne(ctx, c); err != nil {
			e.logger.Error("embedding content", "content_id", c.ID, "slug", c.Slug, "error", err)
			continue
		}
		embedded++
	}
	return embedded, nil
}

func (e *Embedder) embedOne(ctx context.Context, c EmbeddingCandidate) error {
	text := c.Title + "\n\n" + c.Body
	if text == "" {
		return nil
	}
	resp, err := genkit.Embed(ctx, e.g,
		ai.WithEmbedder(e.embedder),
		ai.WithTextDocs(text),
		ai.WithConfig(&genai.EmbedContentConfig{
			OutputDimensionality: genai.Ptr[int32](768),
		}),
	)
	if err != nil {
		return fmt.Errorf("generating embedding: %w", err)
	}
	if len(resp.Embeddings) == 0 || len(resp.Embeddings[0].Embedding) == 0 {
		return nil
	}
	vec := pgvector.NewVector(resp.Embeddings[0].Embedding)
	if err := e.store.UpdateEmbedding(ctx, c.ID, vec); err != nil {
		return fmt.Errorf("storing embedding: %w", err)
	}
	return nil
}
