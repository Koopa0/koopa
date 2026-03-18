package flow

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/content"
)

// ContentPolishInput is the JSON input for the content-polish flow.
type ContentPolishInput struct {
	ContentID string `json:"content_id"`
}

// ContentPolishOutput is the JSON output of the content-polish flow.
type ContentPolishOutput struct {
	OriginalBody string `json:"original_body"`
	PolishedBody string `json:"polished_body"`
}

// ContentPolish implements the content-polish flow using Genkit + Claude.
type ContentPolish struct {
	gf      *genkitFlow
	g       *genkit.Genkit
	model   ai.Model
	content ContentReader
	logger  *slog.Logger
}

// NewContentPolish returns a ContentPolish flow.
func NewContentPolish(g *genkit.Genkit, model ai.Model, content ContentReader, logger *slog.Logger) *ContentPolish {
	cp := &ContentPolish{
		g:       g,
		model:   model,
		content: content,
		logger:  logger,
	}
	cp.gf = genkit.DefineFlow(g, "content-polish", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in ContentPolishInput
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
func (cp *ContentPolish) Name() string { return "content-polish" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (cp *ContentPolish) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return cp.gf.Run(ctx, input)
}

// run is the typed internal implementation.
func (cp *ContentPolish) run(ctx context.Context, in ContentPolishInput) (ContentPolishOutput, error) {
	contentID, err := uuid.Parse(in.ContentID)
	if err != nil {
		return ContentPolishOutput{}, fmt.Errorf("parsing content ID: %w", err)
	}

	c, err := genkit.Run(ctx, "fetch-content", func() (*content.Content, error) {
		return cp.content.Content(ctx, contentID)
	})
	if err != nil {
		return ContentPolishOutput{}, fmt.Errorf("reading content %s: %w", contentID, err)
	}

	cp.logger.Info("content-polish starting", "content_id", contentID, "title", c.Title)

	userPrompt := buildUserPrompt(c)

	polished, err := genkit.Run(ctx, "polish", func() (string, error) {
		resp, err := genkit.Generate(ctx, cp.g,
			ai.WithModel(cp.model),
			ai.WithSystem(polishSystemPrompt),
			ai.WithPrompt(userPrompt),
			ai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.3),
				MaxOutputTokens: 8192,
			}),
		)
		if err != nil {
			return "", fmt.Errorf("generating polish: %w", err)
		}
		if err := checkFinishReason(resp); err != nil {
			return "", err
		}
		return strings.TrimSpace(resp.Text()), nil
	})
	if err != nil {
		return ContentPolishOutput{}, fmt.Errorf("polishing content %s: %w", contentID, err)
	}

	cp.logger.Info("content-polish completed", "content_id", contentID)

	return ContentPolishOutput{
		OriginalBody: c.Body,
		PolishedBody: polished,
	}, nil
}

// NewMockContentPolish returns a mock Flow that returns canned polish output.
func NewMockContentPolish() Flow {
	return &mockFlow{
		name: "content-polish",
		output: ContentPolishOutput{
			OriginalBody: "Mock original body.",
			PolishedBody: "Mock polished body.",
		},
	}
}
