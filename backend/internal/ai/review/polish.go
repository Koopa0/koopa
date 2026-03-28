package review

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	genkitai "github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/ai"
	"github.com/koopa0/blog-backend/internal/content"
)

// PolishInput is the JSON input for the content-polish flow.
type PolishInput struct {
	ContentID string `json:"content_id"`
}

// PolishOutput is the JSON output of the content-polish flow.
type PolishOutput struct {
	OriginalBody string `json:"original_body"`
	PolishedBody string `json:"polished_body"`
}

// ContentReader reads content by ID.
type ContentReader interface {
	Content(ctx context.Context, id uuid.UUID) (*content.Content, error)
}

// Polish implements the content-polish flow using Genkit + Claude.
type Polish struct {
	gf           *ai.GenkitFlow
	g            *genkit.Genkit
	model        genkitai.Model
	systemPrompt string
	content      ContentReader
	logger       *slog.Logger
}

// NewPolish returns a Polish flow.
func NewPolish(g *genkit.Genkit, model genkitai.Model, systemPrompt string, reader ContentReader, logger *slog.Logger) *Polish {
	cp := &Polish{
		g:            g,
		model:        model,
		systemPrompt: systemPrompt,
		content:      reader,
		logger:       logger,
	}
	cp.gf = genkit.DefineFlow(g, "content-polish", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in PolishInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("parsing content-polish input: %w", err)
		}
		out, err := cp.run(ctx, in)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return cp
}

// Name returns the flow name for registry lookup.
func (cp *Polish) Name() string { return "content-polish" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (cp *Polish) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return cp.gf.Run(ctx, input)
}

// run is the typed internal implementation.
func (cp *Polish) run(ctx context.Context, in PolishInput) (PolishOutput, error) {
	contentID, err := uuid.Parse(in.ContentID)
	if err != nil {
		return PolishOutput{}, fmt.Errorf("parsing content ID: %w", err)
	}

	c, err := genkit.Run(ctx, "fetch-content", func() (*content.Content, error) {
		return cp.content.Content(ctx, contentID)
	})
	if err != nil {
		return PolishOutput{}, fmt.Errorf("reading content %s: %w", contentID, err)
	}

	cp.logger.Info("content-polish starting", "content_id", contentID, "title", c.Title)

	userPrompt := ai.BuildUserPrompt(c)

	polished, err := genkit.Run(ctx, "polish", func() (string, error) {
		resp, genErr := genkit.Generate(ctx, cp.g,
			genkitai.WithModel(cp.model),
			genkitai.WithSystem(cp.systemPrompt),
			genkitai.WithPrompt(userPrompt),
			genkitai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.3),
				MaxOutputTokens: 8192,
			}),
		)
		if genErr != nil {
			return "", fmt.Errorf("generating polish: %w", genErr)
		}
		if finishErr := ai.CheckFinishReason(resp); finishErr != nil {
			return "", finishErr
		}
		return strings.TrimSpace(resp.Text()), nil
	})
	if err != nil {
		return PolishOutput{}, fmt.Errorf("polishing content %s: %w", contentID, err)
	}

	cp.logger.Info("content-polish completed", "content_id", contentID)

	return PolishOutput{
		OriginalBody: c.Body,
		PolishedBody: polished,
	}, nil
}
