package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"

	genkitai "github.com/firebase/genkit/go/ai"
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
	Proofread   *ProofreadOutput `json:"proofread"`
	Excerpt     string           `json:"excerpt"`
	Tags        []string         `json:"tags"`
	ReadingTime int              `json:"reading_time"`
}

// ReviewResult is an alias for ProofreadOutput for backward compatibility.
// Referenced by internal/ai/exec tests.
type ReviewResult = ProofreadOutput

// ContentReview is the orchestrator flow that calls sub-flows (proofread, excerpt, tags)
// and handles persistence (embedding, content update, review queue).
type ContentReview struct {
	gf          *GenkitFlow
	g           *genkit.Genkit
	embedder    genkitai.Embedder
	content     ContentReader
	updater     ContentUpdater
	embedWriter EmbeddingWriter
	review      ReviewCreator
	topics      TopicLister
	proofread   Flow
	excerpt     Flow
	tags        Flow
	logger      *slog.Logger
}

// NewContentReview returns a ContentReview orchestrator flow.
// The proofread, excerpt, and tags parameters accept any Flow implementation,
// enabling injection of either real sub-package flows or mocks.
func NewContentReview(
	g *genkit.Genkit,
	embedder genkitai.Embedder,
	contentReader ContentReader,
	updater ContentUpdater,
	embedWriter EmbeddingWriter,
	reviewer ReviewCreator,
	topics TopicLister,
	proofread Flow,
	excerpt Flow,
	tags Flow,
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

// parallelResults holds results from the parallel AI enrichment steps.
type parallelResults struct {
	excerpt     ExcerptOutput
	tags        TagsOutput
	readingTime int
}

// run is the typed internal implementation.
func (cr *ContentReview) run(ctx context.Context, in ContentReviewInput) (ContentReviewOutput, error) {
	contentID, err := uuid.Parse(in.ContentID)
	if err != nil {
		return ContentReviewOutput{}, fmt.Errorf("parsing content ID: %w", err)
	}

	c, err := genkit.Run(ctx, "fetch-content", func() (*content.Content, error) {
		return cr.content.Content(ctx, contentID)
	})
	if err != nil {
		return ContentReviewOutput{}, fmt.Errorf("reading content %s: %w", contentID, err)
	}

	cr.logger.Info("content-review starting", "content_id", contentID, "title", c.Title)

	proofreadResult, err := cr.runProofread(ctx, c, contentID)
	if err != nil {
		return ContentReviewOutput{}, err
	}

	pr, err := cr.runParallelSteps(ctx, c, contentID)
	if err != nil {
		return ContentReviewOutput{}, fmt.Errorf("parallel steps for content %s: %w", contentID, err)
	}

	if err := cr.applyResults(ctx, contentID, proofreadResult, pr); err != nil {
		return ContentReviewOutput{}, fmt.Errorf("updating content %s: %w", contentID, err)
	}

	return ContentReviewOutput{
		Proofread:   proofreadResult,
		Excerpt:     pr.excerpt.Excerpt,
		Tags:        pr.tags.Tags,
		ReadingTime: pr.readingTime,
	}, nil
}

// runProofread executes the sequential proofread sub-flow.
func (cr *ContentReview) runProofread(ctx context.Context, c *content.Content, contentID uuid.UUID) (*ProofreadOutput, error) {
	proofreadInput, _ := json.Marshal(struct {
		ContentType string `json:"content_type"`
		Title       string `json:"title"`
		Body        string `json:"body"`
	}{ContentType: string(c.Type), Title: c.Title, Body: c.Body})

	proofreadRaw, err := cr.proofread.Run(ctx, proofreadInput)
	if err != nil {
		return nil, fmt.Errorf("proofreading content %s: %w", contentID, err)
	}
	var result ProofreadOutput
	if unmarshalErr := json.Unmarshal(proofreadRaw, &result); unmarshalErr != nil {
		return nil, fmt.Errorf("parsing proofread output: %w", unmarshalErr)
	}

	cr.logger.Info("proofread complete", "content_id", contentID, "level", result.Level)
	return &result, nil
}

// runParallelSteps runs excerpt, tags, reading time, and embedding generation concurrently.
func (cr *ContentReview) runParallelSteps(ctx context.Context, c *content.Content, contentID uuid.UUID) (parallelResults, error) {
	var pr parallelResults
	eg, gctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		excerptInput, _ := json.Marshal(struct {
			ContentType string `json:"content_type"`
			Title       string `json:"title"`
			Body        string `json:"body"`
		}{ContentType: string(c.Type), Title: c.Title, Body: c.Body})

		excerptRaw, excerptErr := cr.excerpt.Run(gctx, excerptInput)
		if excerptErr != nil {
			return excerptErr
		}
		return json.Unmarshal(excerptRaw, &pr.excerpt)
	})

	eg.Go(func() error {
		return cr.runTagsStep(gctx, c, &pr.tags)
	})

	eg.Go(func() error {
		var rtErr error
		pr.readingTime, rtErr = genkit.Run(gctx, "reading-time", func() (int, error) {
			return estimateReadingTime(c.Body), nil
		})
		return rtErr
	})

	eg.Go(func() error {
		return cr.runEmbeddingStep(gctx, c.Body, contentID)
	})

	return pr, eg.Wait()
}

// runTagsStep fetches topic slugs and runs the tags sub-flow.
func (cr *ContentReview) runTagsStep(ctx context.Context, c *content.Content, out *TagsOutput) error {
	slugs, err := cr.topics.AllTopicSlugs(ctx)
	if err != nil {
		return fmt.Errorf("listing topics: %w", err)
	}

	topicSlugs := make([]string, len(slugs))
	topicNames := make([]string, len(slugs))
	for i, s := range slugs {
		topicSlugs[i] = s.Slug
		topicNames[i] = s.Name
	}

	tagsInput, _ := json.Marshal(struct {
		ContentType string   `json:"content_type"`
		Title       string   `json:"title"`
		Body        string   `json:"body"`
		TopicSlugs  []string `json:"topic_slugs"`
		TopicNames  []string `json:"topic_names"`
	}{
		ContentType: string(c.Type),
		Title:       c.Title,
		Body:        c.Body,
		TopicSlugs:  topicSlugs,
		TopicNames:  topicNames,
	})

	tagsRaw, tagsErr := cr.tags.Run(ctx, tagsInput)
	if tagsErr != nil {
		return tagsErr
	}
	return json.Unmarshal(tagsRaw, out)
}

// runEmbeddingStep generates and stores a content embedding.
func (cr *ContentReview) runEmbeddingStep(ctx context.Context, body string, contentID uuid.UUID) error {
	_, err := genkit.Run(ctx, "generate-embedding", func() (any, error) {
		resp, embedErr := genkit.Embed(ctx, cr.g,
			genkitai.WithEmbedder(cr.embedder),
			genkitai.WithTextDocs(body),
			genkitai.WithConfig(&genai.EmbedContentConfig{
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
		if storeErr := cr.embedWriter.UpdateEmbedding(ctx, contentID, vec); storeErr != nil {
			return nil, fmt.Errorf("storing embedding: %w", storeErr)
		}
		cr.logger.Info("embedding stored", "content_id", contentID, "dimensions", len(resp.Embeddings[0].Embedding))
		return nil, nil
	})
	return err
}

// applyResults updates content with AI results and creates review entry if needed.
func (cr *ContentReview) applyResults(ctx context.Context, contentID uuid.UUID, proofread *ProofreadOutput, pr parallelResults) error {
	_, err := genkit.Run(ctx, "update-content", func() (any, error) {
		aiMetadata, _ := json.Marshal(proofread) // safe: struct contains only JSON-compatible types
		updateParams := &content.UpdateParams{
			Excerpt:     &pr.excerpt.Excerpt,
			ReadingTime: &pr.readingTime,
			AIMetadata:  aiMetadata,
		}
		if len(pr.tags.Tags) > 0 {
			updateParams.Tags = pr.tags.Tags
		}
		if _, updateErr := cr.updater.UpdateContent(ctx, contentID, updateParams); updateErr != nil {
			return nil, fmt.Errorf("updating content: %w", updateErr)
		}

		if proofread.Level != "auto" {
			notes := proofread.Notes
			if _, reviewErr := cr.review.Create(ctx, contentID, proofread.Level, &notes); reviewErr != nil {
				return nil, fmt.Errorf("creating review: %w", reviewErr)
			}
			cr.logger.Info("content sent to review queue", "content_id", contentID, "level", proofread.Level)
		} else {
			cr.logger.Info("content auto-approved", "content_id", contentID)
		}
		return nil, nil
	})
	return err
}

// NewMockContentReview returns a mock Flow that returns canned output without calling any AI or database.
func NewMockContentReview() Flow {
	return &mockFlow{
		name: "content-review",
		output: ContentReviewOutput{
			Proofread:   &ProofreadOutput{Level: "auto", Notes: "mock mode", Corrections: []string{}},
			Excerpt:     "Mock excerpt for testing.",
			Tags:        []string{},
			ReadingTime: 1,
		},
	}
}

// NewMockContentProofread returns a mock Flow that returns canned proofread output.
func NewMockContentProofread() Flow {
	return &mockFlow{
		name: "content-proofread",
		output: ProofreadOutput{
			Level:       "auto",
			Notes:       "mock mode",
			Corrections: []string{},
		},
	}
}

// NewMockContentExcerpt returns a mock Flow that returns canned excerpt output.
func NewMockContentExcerpt() Flow {
	return &mockFlow{
		name: "content-excerpt",
		output: ExcerptOutput{
			Excerpt: "Mock excerpt for testing.",
		},
	}
}

// NewMockContentTags returns a mock Flow that returns canned tags output.
func NewMockContentTags() Flow {
	return &mockFlow{
		name: "content-tags",
		output: TagsOutput{
			Tags: []string{},
		},
	}
}

// NewMockContentPolish returns a mock Flow that returns canned polish output.
func NewMockContentPolish() Flow {
	return &mockFlow{
		name: "content-polish",
		output: struct {
			OriginalBody string `json:"original_body"`
			PolishedBody string `json:"polished_body"`
		}{
			OriginalBody: "Mock original body.",
			PolishedBody: "Mock polished body.",
		},
	}
}

// maxPromptBodyRunes caps prompt body length to prevent excessive token consumption.
const maxPromptBodyRunes = 50000

// TruncateBodyRunes truncates body to maxPromptBodyRunes runes for LLM prompt safety.
// Exported for use by sub-packages.
func TruncateBodyRunes(body string) string {
	runes := []rune(body)
	if len(runes) <= maxPromptBodyRunes {
		return body
	}
	return string(runes[:maxPromptBodyRunes]) + "\n...[truncated]"
}

// BuildUserPrompt assembles the user prompt from content fields.
// Exported for use by sub-packages.
func BuildUserPrompt(c *content.Content) string {
	return fmt.Sprintf("Type: %s\nTitle: %s\n\nBody:\n%s", c.Type, c.Title, c.Body)
}

// estimateReadingTime calculates reading time in minutes.
// Rough CJK estimate: character count / 2 = word equivalent, then / 250 wpm.
func estimateReadingTime(body string) int {
	words := utf8.RuneCountInString(body) / 2
	if words == 0 {
		words = len(strings.Fields(body))
	}
	minutes := max(words/250, 1)
	return minutes
}

// ParseJSONLoose extracts JSON from LLM output that may be wrapped in markdown.
// Exported for use by sub-packages.
func ParseJSONLoose(text string, v any) error {
	text = strings.TrimSpace(text)

	// Try direct unmarshal first
	if err := json.Unmarshal([]byte(text), v); err == nil {
		return nil
	}

	// Try extracting from ```json blocks
	if _, after, ok := strings.Cut(text, "```json"); ok {
		rest := after
		if before, _, ok := strings.Cut(rest, "```"); ok {
			if err := json.Unmarshal([]byte(strings.TrimSpace(before)), v); err == nil {
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
