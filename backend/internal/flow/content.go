package flow

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
	"github.com/pgvector/pgvector-go"
	"golang.org/x/sync/errgroup"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/review"
	"github.com/koopa0/blog-backend/internal/topic"
)

// ContentReader reads content by ID.
type ContentReader interface {
	Content(ctx context.Context, id uuid.UUID) (*content.Content, error)
}

// ContentUpdater updates content fields.
type ContentUpdater interface {
	UpdateContent(ctx context.Context, id uuid.UUID, p *content.UpdateParams) (*content.Content, error)
}

// ReviewCreator creates a review queue entry.
type ReviewCreator interface {
	Create(ctx context.Context, contentID uuid.UUID, reviewLevel string, notes *string) (*review.Review, error)
}

// EmbeddingWriter writes embedding vectors to content.
type EmbeddingWriter interface {
	UpdateEmbedding(ctx context.Context, id uuid.UUID, embedding pgvector.Vector) error
}

// TopicLister returns all topic slugs for constrained tag classification.
type TopicLister interface {
	AllTopicSlugs(ctx context.Context) ([]topic.Slug, error)
}

// ContentReviewInput is the JSON input for the content-review flow.
type ContentReviewInput struct {
	ContentID string `json:"content_id"`
}

// ContentReviewOutput is the JSON output of the content-review flow.
type ContentReviewOutput struct {
	Proofread   *ContentProofreadOutput `json:"proofread"`
	Excerpt     string                  `json:"excerpt"`
	Tags        []string                `json:"tags"`
	ReadingTime int                     `json:"reading_time"`
}

// ReviewResult is an alias for ContentProofreadOutput.
// Kept for backward compatibility: referenced by cmd/calibrate and internal/flowrun tests.
type ReviewResult = ContentProofreadOutput

// ContentReview is the orchestrator flow that calls sub-flows (proofread, excerpt, tags)
// and handles persistence (embedding, content update, review queue).
type ContentReview struct {
	gf          *genkitFlow
	g           *genkit.Genkit
	embedder    ai.Embedder
	content     ContentReader
	updater     ContentUpdater
	embedWriter EmbeddingWriter
	review      ReviewCreator
	topics      TopicLister
	proofread   *ContentProofread
	excerpt     *ContentExcerpt
	tags        *ContentTags
	logger      *slog.Logger
}

// NewContentReview returns a ContentReview orchestrator flow.
func NewContentReview(
	g *genkit.Genkit,
	embedder ai.Embedder,
	contentReader ContentReader,
	updater ContentUpdater,
	embedWriter EmbeddingWriter,
	reviewer ReviewCreator,
	topics TopicLister,
	proofread *ContentProofread,
	excerpt *ContentExcerpt,
	tags *ContentTags,
	logger *slog.Logger,
) *ContentReview {
	cr := &ContentReview{
		g:           g,
		embedder:    embedder,
		content:     contentReader,
		updater:     updater,
		embedWriter: embedWriter,
		review:      reviewer,
		topics:      topics,
		proofread:   proofread,
		excerpt:     excerpt,
		tags:        tags,
		logger:      logger,
	}
	cr.gf = genkit.DefineFlow(g, "content-review", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in ContentReviewInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("parsing content-review input: %w", err)
		}
		out, err := cr.run(ctx, in)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return cr
}

// Name returns the flow name for registry lookup.
func (cr *ContentReview) Name() string { return "content-review" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (cr *ContentReview) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return cr.gf.Run(ctx, input)
}

// run is the typed internal implementation.
func (cr *ContentReview) run(ctx context.Context, in ContentReviewInput) (ContentReviewOutput, error) {
	contentID, err := uuid.Parse(in.ContentID)
	if err != nil {
		return ContentReviewOutput{}, fmt.Errorf("parsing content ID: %w", err)
	}

	// Step: fetch content (traced)
	c, err := genkit.Run(ctx, "fetch-content", func() (*content.Content, error) {
		return cr.content.Content(ctx, contentID)
	})
	if err != nil {
		return ContentReviewOutput{}, fmt.Errorf("reading content %s: %w", contentID, err)
	}

	cr.logger.Info("content-review starting", "content_id", contentID, "title", c.Title)

	// Step 1 (sequential): proofread via sub-flow
	proofreadResult, err := cr.proofread.run(ctx, ContentProofreadInput{
		ContentType: string(c.Type),
		Title:       c.Title,
		Body:        c.Body,
	})
	if err != nil {
		return ContentReviewOutput{}, fmt.Errorf("proofreading content %s: %w", contentID, err)
	}

	cr.logger.Info("proofread complete", "content_id", contentID, "level", proofreadResult.Level)

	// Steps 2-5 (parallel): excerpt, tags, reading time, embedding
	var (
		excerptResult ContentExcerptOutput
		tagsResult    ContentTagsOutput
		readingTime   int
	)

	eg, gctx := errgroup.WithContext(ctx)

	// Step 2: excerpt via sub-flow
	eg.Go(func() error {
		var excerptErr error
		excerptResult, excerptErr = cr.excerpt.run(gctx, ContentExcerptInput{
			ContentType: string(c.Type),
			Title:       c.Title,
			Body:        c.Body,
		})
		return excerptErr
	})

	// Step 3: tags via sub-flow (fetch topics first, pass as input)
	eg.Go(func() error {
		slugs, slugsErr := cr.topics.AllTopicSlugs(gctx)
		if slugsErr != nil {
			return fmt.Errorf("listing topics: %w", slugsErr)
		}

		topicSlugs := make([]string, len(slugs))
		topicNames := make([]string, len(slugs))
		for i, s := range slugs {
			topicSlugs[i] = s.Slug
			topicNames[i] = s.Name
		}

		var tagsErr error
		tagsResult, tagsErr = cr.tags.run(gctx, &ContentTagsInput{
			ContentType: string(c.Type),
			Title:       c.Title,
			Body:        c.Body,
			TopicSlugs:  topicSlugs,
			TopicNames:  topicNames,
		})
		return tagsErr
	})

	// Step 4: reading time (pure computation, traced)
	eg.Go(func() error {
		var rtErr error
		readingTime, rtErr = genkit.Run(gctx, "reading-time", func() (int, error) {
			return estimateReadingTime(c.Body), nil
		})
		return rtErr
	})

	// Step 5: generate embedding
	eg.Go(func() error {
		_, embedRunErr := genkit.Run(gctx, "generate-embedding", func() (any, error) {
			resp, embedErr := genkit.Embed(gctx, cr.g,
				ai.WithEmbedder(cr.embedder),
				ai.WithTextDocs(c.Body),
				ai.WithConfig(&genai.EmbedContentConfig{
					OutputDimensionality: genai.Ptr[int32](768),
				}),
			)
			if embedErr != nil {
				return nil, fmt.Errorf("generating embedding: %w", embedErr)
			}
			if len(resp.Embeddings) == 0 || len(resp.Embeddings[0].Embedding) == 0 {
				cr.logger.Warn("empty embedding response", "content_id", contentID)
				return nil, nil
			}
			vec := pgvector.NewVector(resp.Embeddings[0].Embedding)
			if storeErr := cr.embedWriter.UpdateEmbedding(gctx, contentID, vec); storeErr != nil {
				return nil, fmt.Errorf("storing embedding: %w", storeErr)
			}
			cr.logger.Info("embedding stored", "content_id", contentID, "dimensions", len(resp.Embeddings[0].Embedding))
			return nil, nil
		})
		return embedRunErr
	})

	if waitErr := eg.Wait(); waitErr != nil {
		return ContentReviewOutput{}, fmt.Errorf("parallel steps for content %s: %w", contentID, waitErr)
	}

	// Step: update content with AI results (traced)
	_, err = genkit.Run(ctx, "update-content", func() (any, error) {
		aiMetadata, _ := json.Marshal(proofreadResult) // safe: struct contains only JSON-compatible types
		updateParams := &content.UpdateParams{
			Excerpt:     &excerptResult.Excerpt,
			ReadingTime: &readingTime,
			AIMetadata:  aiMetadata,
		}
		if len(tagsResult.Tags) > 0 {
			updateParams.Tags = tagsResult.Tags
		}
		if _, updateErr := cr.updater.UpdateContent(ctx, contentID, updateParams); updateErr != nil {
			return nil, fmt.Errorf("updating content: %w", updateErr)
		}

		// Create review queue entry if not auto-publishable
		if proofreadResult.Level != "auto" {
			notes := proofreadResult.Notes
			if _, reviewErr := cr.review.Create(ctx, contentID, proofreadResult.Level, &notes); reviewErr != nil {
				return nil, fmt.Errorf("creating review: %w", reviewErr)
			}
			cr.logger.Info("content sent to review queue", "content_id", contentID, "level", proofreadResult.Level)
		} else {
			cr.logger.Info("content auto-approved", "content_id", contentID)
		}
		return nil, nil
	})
	if err != nil {
		return ContentReviewOutput{}, fmt.Errorf("updating content %s: %w", contentID, err)
	}

	return ContentReviewOutput{
		Proofread:   &proofreadResult,
		Excerpt:     excerptResult.Excerpt,
		Tags:        tagsResult.Tags,
		ReadingTime: readingTime,
	}, nil
}

// NewMockContentReview returns a mock Flow that returns canned output without calling any AI or database.
func NewMockContentReview() Flow {
	return &mockFlow{
		name: "content-review",
		output: ContentReviewOutput{
			Proofread:   &ContentProofreadOutput{Level: "auto", Notes: "mock mode", Corrections: []string{}},
			Excerpt:     "Mock excerpt for testing.",
			Tags:        []string{},
			ReadingTime: 1,
		},
	}
}

// maxPromptBodyRunes caps prompt body length to prevent excessive token consumption.
const maxPromptBodyRunes = 50000

// truncateBodyRunes truncates body to maxPromptBodyRunes runes for LLM prompt safety.
func truncateBodyRunes(body string) string {
	runes := []rune(body)
	if len(runes) <= maxPromptBodyRunes {
		return body
	}
	return string(runes[:maxPromptBodyRunes]) + "\n...[truncated]"
}

// buildUserPrompt assembles the user prompt from content fields.
func buildUserPrompt(c *content.Content) string {
	return fmt.Sprintf("Type: %s\nTitle: %s\n\nBody:\n%s", c.Type, c.Title, c.Body)
}

// estimateReadingTime calculates reading time in minutes.
// Rough CJK estimate: character count / 2 = word equivalent, then / 250 wpm.
func estimateReadingTime(body string) int {
	words := utf8.RuneCountInString(body) / 2
	if words == 0 {
		words = len(strings.Fields(body))
	}
	minutes := words / 250
	if minutes < 1 {
		minutes = 1
	}
	return minutes
}

// parseJSONLoose extracts JSON from LLM output that may be wrapped in markdown.
func parseJSONLoose(text string, v any) error {
	text = strings.TrimSpace(text)

	// Try direct unmarshal first
	if err := json.Unmarshal([]byte(text), v); err == nil {
		return nil
	}

	// Try extracting from ```json blocks
	if start := strings.Index(text, "```json"); start >= 0 {
		rest := text[start+7:]
		if end := strings.Index(rest, "```"); end >= 0 {
			if err := json.Unmarshal([]byte(strings.TrimSpace(rest[:end])), v); err == nil {
				return nil
			}
		}
	}

	// Find first [ or { to last ] or }
	firstArr := strings.IndexByte(text, '[')
	firstObj := strings.IndexByte(text, '{')
	lastArr := strings.LastIndexByte(text, ']')
	lastObj := strings.LastIndexByte(text, '}')

	if firstArr >= 0 && lastArr > firstArr {
		if err := json.Unmarshal([]byte(text[firstArr:lastArr+1]), v); err == nil {
			return nil
		}
	}
	if firstObj >= 0 && lastObj > firstObj {
		if err := json.Unmarshal([]byte(text[firstObj:lastObj+1]), v); err == nil {
			return nil
		}
	}

	return fmt.Errorf("no valid JSON found in response: %.100s", text)
}
