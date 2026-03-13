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
	UpdateContent(ctx context.Context, id uuid.UUID, p content.UpdateParams) (*content.Content, error)
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
	AllTopicSlugs(ctx context.Context) ([]topic.TopicSlug, error)
}

// ContentReviewInput is the JSON input for the content-review flow.
type ContentReviewInput struct {
	ContentID string `json:"content_id"`
}

// ContentReviewOutput is the JSON output of the content-review flow.
type ContentReviewOutput struct {
	Proofread   *ReviewResult `json:"proofread"`
	Excerpt     string        `json:"excerpt"`
	Tags        []string      `json:"tags"`
	ReadingTime int           `json:"reading_time"`
}

// ReviewResult is the structured output from the review prompt.
type ReviewResult struct {
	Level       string   `json:"level"`
	Notes       string   `json:"notes"`
	Corrections []string `json:"corrections"`
}

// ContentReview implements the content-review flow using Genkit.
type ContentReview struct {
	gf          *genkitFlow
	g           *genkit.Genkit
	model       ai.Model
	embedder    ai.Embedder
	content     ContentReader
	updater     ContentUpdater
	embedWriter EmbeddingWriter
	review      ReviewCreator
	topics      TopicLister
	logger      *slog.Logger
}

// NewContentReview returns a ContentReview flow.
func NewContentReview(
	g *genkit.Genkit,
	model ai.Model,
	embedder ai.Embedder,
	contentReader ContentReader,
	updater ContentUpdater,
	embedWriter EmbeddingWriter,
	review ReviewCreator,
	topics TopicLister,
	logger *slog.Logger,
) *ContentReview {
	cr := &ContentReview{
		g:           g,
		model:       model,
		embedder:    embedder,
		content:     contentReader,
		updater:     updater,
		embedWriter: embedWriter,
		review:      review,
		topics:      topics,
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

	userPrompt := buildUserPrompt(c)

	// Step 1 (sequential): proofread via GenerateData[ReviewResult]
	reviewResult, err := genkit.Run(ctx, "proofread", func() (*ReviewResult, error) {
		result, _, err := genkit.GenerateData[ReviewResult](ctx, cr.g,
			ai.WithModel(cr.model),
			ai.WithSystem(reviewSystemPrompt),
			ai.WithPrompt(userPrompt),
			ai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.3),
				MaxOutputTokens: 4096,
			}),
		)
		if err != nil {
			return nil, fmt.Errorf("generating review: %w", err)
		}
		return result, nil
	})
	if err != nil {
		return ContentReviewOutput{}, fmt.Errorf("proofreading content %s: %w", contentID, err)
	}

	cr.logger.Info("proofread complete", "content_id", contentID, "level", reviewResult.Level)

	// Steps 2-5 (parallel)
	var (
		excerpt     string
		tags        []string
		readingTime int
	)

	g, gctx := errgroup.WithContext(ctx)

	// Step 2: excerpt
	g.Go(func() error {
		resp, err := genkit.Generate(gctx, cr.g,
			ai.WithModel(cr.model),
			ai.WithSystem(excerptSystemPrompt),
			ai.WithPrompt(userPrompt),
			ai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.5),
				MaxOutputTokens: 256,
			}),
		)
		if err != nil {
			return fmt.Errorf("generating excerpt: %w", err)
		}
		excerpt = strings.TrimSpace(resp.Text())
		return nil
	})

	// Step 3: tags (constrained to existing topics)
	g.Go(func() error {
		slugs, err := cr.topics.AllTopicSlugs(gctx)
		if err != nil {
			return fmt.Errorf("listing topics: %w", err)
		}

		tagsUserPrompt := buildTagsUserPrompt(c, slugs)

		resp, err := genkit.Generate(gctx, cr.g,
			ai.WithModel(cr.model),
			ai.WithSystem(tagsSystemPrompt),
			ai.WithPrompt(tagsUserPrompt),
			ai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.2),
				MaxOutputTokens: 512,
			}),
		)
		if err != nil {
			return fmt.Errorf("generating tags: %w", err)
		}

		var suggested []string
		if err := parseJSONLoose(resp.Text(), &suggested); err != nil {
			return fmt.Errorf("parsing tags response: %w", err)
		}

		// Filter to only existing slugs
		existing := make(map[string]bool, len(slugs))
		for _, s := range slugs {
			existing[s.Slug] = true
		}
		for _, tag := range suggested {
			if existing[tag] {
				tags = append(tags, tag)
			}
		}
		return nil
	})

	// Step 4: reading time (pure computation, traced)
	g.Go(func() error {
		var err error
		readingTime, err = genkit.Run(gctx, "reading-time", func() (int, error) {
			return estimateReadingTime(c.Body), nil
		})
		return err
	})

	// Step 5: generate embedding
	g.Go(func() error {
		_, err := genkit.Run(gctx, "generate-embedding", func() (any, error) {
			resp, err := genkit.Embed(gctx, cr.g,
				ai.WithEmbedder(cr.embedder),
				ai.WithTextDocs(c.Body),
				ai.WithConfig(&genai.EmbedContentConfig{
					OutputDimensionality: genai.Ptr[int32](768),
				}),
			)
			if err != nil {
				return nil, fmt.Errorf("generating embedding: %w", err)
			}
			if len(resp.Embeddings) == 0 || len(resp.Embeddings[0].Embedding) == 0 {
				cr.logger.Warn("empty embedding response", "content_id", contentID)
				return nil, nil
			}
			vec := pgvector.NewVector(resp.Embeddings[0].Embedding)
			if err := cr.embedWriter.UpdateEmbedding(gctx, contentID, vec); err != nil {
				return nil, fmt.Errorf("storing embedding: %w", err)
			}
			cr.logger.Info("embedding stored", "content_id", contentID, "dimensions", len(resp.Embeddings[0].Embedding))
			return nil, nil
		})
		return err
	})

	if err := g.Wait(); err != nil {
		return ContentReviewOutput{}, fmt.Errorf("parallel steps for content %s: %w", contentID, err)
	}

	// Step: update content with AI results (traced)
	_, err = genkit.Run(ctx, "update-content", func() (any, error) {
		aiMetadata, _ := json.Marshal(reviewResult)
		updateParams := content.UpdateParams{
			Excerpt:     &excerpt,
			ReadingTime: &readingTime,
			AIMetadata:  aiMetadata,
		}
		if len(tags) > 0 {
			updateParams.Tags = tags
		}
		if _, err := cr.updater.UpdateContent(ctx, contentID, updateParams); err != nil {
			return nil, fmt.Errorf("updating content: %w", err)
		}

		// Create review queue entry if not auto-publishable
		if reviewResult.Level != "auto" {
			notes := reviewResult.Notes
			if _, err := cr.review.Create(ctx, contentID, reviewResult.Level, &notes); err != nil {
				return nil, fmt.Errorf("creating review: %w", err)
			}
			cr.logger.Info("content sent to review queue", "content_id", contentID, "level", reviewResult.Level)
		} else {
			cr.logger.Info("content auto-approved", "content_id", contentID)
		}
		return nil, nil
	})
	if err != nil {
		return ContentReviewOutput{}, fmt.Errorf("updating content %s: %w", contentID, err)
	}

	return ContentReviewOutput{
		Proofread:   reviewResult,
		Excerpt:     excerpt,
		Tags:        tags,
		ReadingTime: readingTime,
	}, nil
}

// NewMockContentReview returns a mock Flow that returns canned output without calling any AI or database.
func NewMockContentReview() Flow {
	return &mockFlow{
		name: "content-review",
		output: ContentReviewOutput{
			Proofread:   &ReviewResult{Level: "auto", Notes: "mock mode", Corrections: []string{}},
			Excerpt:     "Mock excerpt for testing.",
			Tags:        []string{},
			ReadingTime: 1,
		},
	}
}

// buildUserPrompt assembles the user prompt from content fields.
func buildUserPrompt(c *content.Content) string {
	return fmt.Sprintf("Type: %s\nTitle: %s\n\nBody:\n%s", c.Type, c.Title, c.Body)
}

// buildTagsUserPrompt assembles the user prompt with content + topic list.
func buildTagsUserPrompt(c *content.Content, topics []topic.TopicSlug) string {
	var b strings.Builder
	b.WriteString("Existing tags:\n")
	for _, t := range topics {
		fmt.Fprintf(&b, "- %s (%s)\n", t.Slug, t.Name)
	}
	b.WriteString("\n")
	b.WriteString(buildUserPrompt(c))
	return b.String()
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
