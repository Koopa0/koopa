package flow

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"google.golang.org/genai"
)

// ContentTagsInput is the JSON input for the content-tags sub-flow.
type ContentTagsInput struct {
	ContentType string   `json:"content_type"`
	Title       string   `json:"title"`
	Body        string   `json:"body"`
	TopicSlugs  []string `json:"topic_slugs"`
	TopicNames  []string `json:"topic_names"`
}

// ContentTagsOutput is the JSON output of the content-tags sub-flow.
type ContentTagsOutput struct {
	Tags []string `json:"tags"`
}

// ContentTags implements the content-tags sub-flow.
// It is pure: takes text + topic list as input, returns suggested tags, no DB access.
type ContentTags struct {
	gf     *genkitFlow
	g      *genkit.Genkit
	model  ai.Model
	logger *slog.Logger
}

// NewContentTags returns a ContentTags flow.
func NewContentTags(g *genkit.Genkit, model ai.Model, logger *slog.Logger) *ContentTags {
	ct := &ContentTags{
		g:      g,
		model:  model,
		logger: logger,
	}
	ct.gf = genkit.DefineFlow(g, "content-tags", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in ContentTagsInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("parsing content-tags input: %w", err)
		}
		out, err := ct.run(ctx, in)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return ct
}

// Name returns the flow name for registry lookup.
func (ct *ContentTags) Name() string { return "content-tags" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (ct *ContentTags) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return ct.gf.Run(ctx, input)
}

// run is the typed internal implementation.
func (ct *ContentTags) run(ctx context.Context, in ContentTagsInput) (ContentTagsOutput, error) {
	ct.logger.Info("content-tags starting", "title", in.Title)

	// Build topic list for the prompt.
	var topicList strings.Builder
	topicList.WriteString("Existing tags:\n")
	for i, slug := range in.TopicSlugs {
		name := slug
		if i < len(in.TopicNames) {
			name = in.TopicNames[i]
		}
		fmt.Fprintf(&topicList, "- %s (%s)\n", slug, name)
	}

	userPrompt := fmt.Sprintf("%s\nType: %s\nTitle: %s\n\nBody:\n%s",
		topicList.String(), in.ContentType, in.Title, truncateBodyRunes(in.Body))

	tags, err := genkit.Run(ctx, "tags", func() ([]string, error) {
		suggestedPtr, resp, err := genkit.GenerateData[[]string](ctx, ct.g,
			ai.WithModel(ct.model),
			ai.WithSystem(tagsSystemPrompt),
			ai.WithPrompt(userPrompt),
			ai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.2),
				MaxOutputTokens: 512,
			}),
		)
		if err != nil {
			return nil, fmt.Errorf("calling llm: %w", err)
		}
		if err := checkFinishReason(resp); err != nil {
			return nil, err
		}

		var suggested []string
		if suggestedPtr != nil {
			suggested = *suggestedPtr
		}

		// Filter to only existing slugs.
		existing := make(map[string]struct{}, len(in.TopicSlugs))
		for _, s := range in.TopicSlugs {
			existing[s] = struct{}{}
		}
		var filtered []string
		for _, tag := range suggested {
			if _, ok := existing[tag]; ok {
				filtered = append(filtered, tag)
			}
		}
		if len(filtered) == 0 && len(suggested) > 0 {
			ct.logger.Warn("all LLM-suggested tags rejected by allowlist",
				"title", in.Title, "suggested", suggested)
		}
		return filtered, nil
	})
	if err != nil {
		return ContentTagsOutput{}, fmt.Errorf("generating tags: %w", err)
	}

	ct.logger.Info("content-tags complete", "title", in.Title, "count", len(tags))
	return ContentTagsOutput{Tags: tags}, nil
}

// NewMockContentTags returns a mock Flow that returns canned tags output.
func NewMockContentTags() Flow {
	return &mockFlow{
		name: "content-tags",
		output: ContentTagsOutput{
			Tags: []string{},
		},
	}
}
