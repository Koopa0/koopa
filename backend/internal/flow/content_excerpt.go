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

// ContentExcerptInput is the JSON input for the content-excerpt sub-flow.
type ContentExcerptInput struct {
	ContentType string `json:"content_type"`
	Title       string `json:"title"`
	Body        string `json:"body"`
}

// ContentExcerptOutput is the JSON output of the content-excerpt sub-flow.
type ContentExcerptOutput struct {
	Excerpt string `json:"excerpt"`
}

// ContentExcerpt implements the content-excerpt sub-flow.
// It is pure: takes text input, returns excerpt string, no DB access.
type ContentExcerpt struct {
	gf     *genkitFlow
	g      *genkit.Genkit
	model  ai.Model
	logger *slog.Logger
}

// NewContentExcerpt returns a ContentExcerpt flow.
func NewContentExcerpt(g *genkit.Genkit, model ai.Model, logger *slog.Logger) *ContentExcerpt {
	ce := &ContentExcerpt{
		g:      g,
		model:  model,
		logger: logger,
	}
	ce.gf = genkit.DefineFlow(g, "content-excerpt", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in ContentExcerptInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("parsing content-excerpt input: %w", err)
		}
		out, err := ce.run(ctx, in)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return ce
}

// Name returns the flow name for registry lookup.
func (ce *ContentExcerpt) Name() string { return "content-excerpt" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (ce *ContentExcerpt) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return ce.gf.Run(ctx, input)
}

// run is the typed internal implementation.
func (ce *ContentExcerpt) run(ctx context.Context, in ContentExcerptInput) (ContentExcerptOutput, error) {
	ce.logger.Info("content-excerpt starting", "title", in.Title)

	userPrompt := fmt.Sprintf("Type: %s\nTitle: %s\n\nBody:\n%s", in.ContentType, in.Title, truncateBodyRunes(in.Body))

	excerpt, err := genkit.Run(ctx, "excerpt", func() (string, error) {
		resp, err := genkit.Generate(ctx, ce.g,
			ai.WithModel(ce.model),
			ai.WithSystem(excerptSystemPrompt),
			ai.WithPrompt(userPrompt),
			ai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.5),
				MaxOutputTokens: 256,
			}),
		)
		if err != nil {
			return "", fmt.Errorf("calling llm: %w", err)
		}
		if err := checkFinishReason(resp); err != nil {
			return "", err
		}
		return strings.TrimSpace(resp.Text()), nil
	})
	if err != nil {
		return ContentExcerptOutput{}, fmt.Errorf("generating excerpt: %w", err)
	}

	ce.logger.Info("content-excerpt complete", "title", in.Title)
	return ContentExcerptOutput{Excerpt: excerpt}, nil
}

// NewMockContentExcerpt returns a mock Flow that returns canned excerpt output.
func NewMockContentExcerpt() Flow {
	return &mockFlow{
		name: "content-excerpt",
		output: ContentExcerptOutput{
			Excerpt: "Mock excerpt for testing.",
		},
	}
}
