package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	genkitai "github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"google.golang.org/genai"
)

// ExcerptInput is the JSON input for the content-excerpt sub-flow.
type ExcerptInput struct {
	ContentType string `json:"content_type"`
	Title       string `json:"title"`
	Body        string `json:"body"`
}

// ExcerptOutput is the JSON output of the content-excerpt sub-flow.
type ExcerptOutput struct {
	Excerpt string `json:"excerpt"`
}

// Excerpt implements the content-excerpt sub-flow.
// It is pure: takes text input, returns excerpt string, no DB access.
type Excerpt struct {
	gf           *GenkitFlow
	g            *genkit.Genkit
	model        genkitai.Model
	systemPrompt string
	logger       *slog.Logger
}

// NewExcerpt returns an Excerpt flow.
func NewExcerpt(g *genkit.Genkit, model genkitai.Model, systemPrompt string, logger *slog.Logger) *Excerpt {
	ce := &Excerpt{
		g:            g,
		model:        model,
		systemPrompt: systemPrompt,
		logger:       logger,
	}
	ce.gf = genkit.DefineFlow(g, "content-excerpt", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in ExcerptInput
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
func (ce *Excerpt) Name() string { return "content-excerpt" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (ce *Excerpt) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return ce.gf.Run(ctx, input)
}

// run is the typed internal implementation.
func (ce *Excerpt) run(ctx context.Context, in ExcerptInput) (ExcerptOutput, error) {
	ce.logger.Info("content-excerpt starting", "title", in.Title)

	userPrompt := fmt.Sprintf("Type: %s\nTitle: %s\n\nBody:\n%s", in.ContentType, in.Title, TruncateBodyRunes(in.Body))

	excerpt, err := genkit.Run(ctx, "excerpt", func() (string, error) {
		resp, err := genkit.Generate(ctx, ce.g,
			genkitai.WithModel(ce.model),
			genkitai.WithSystem(ce.systemPrompt),
			genkitai.WithPrompt(userPrompt),
			genkitai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.5),
				MaxOutputTokens: 256,
			}),
		)
		if err != nil {
			return "", fmt.Errorf("calling llm: %w", err)
		}
		if err := CheckFinishReason(resp); err != nil {
			return "", err
		}
		return strings.TrimSpace(resp.Text()), nil
	})
	if err != nil {
		return ExcerptOutput{}, fmt.Errorf("generating excerpt: %w", err)
	}

	ce.logger.Info("content-excerpt complete", "title", in.Title)
	return ExcerptOutput{Excerpt: excerpt}, nil
}
