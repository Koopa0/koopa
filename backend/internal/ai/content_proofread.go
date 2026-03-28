package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	genkitai "github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"google.golang.org/genai"
)

// ContentProofreadInput is the JSON input for the content-proofread sub-flow.
type ContentProofreadInput struct {
	ContentType string `json:"content_type"`
	Title       string `json:"title"`
	Body        string `json:"body"`
}

// ContentProofreadOutput is the JSON output of the content-proofread sub-flow.
type ContentProofreadOutput struct {
	Level       string   `json:"level"`
	Notes       string   `json:"notes"`
	Corrections []string `json:"corrections"`
}

// ContentProofread implements the content-proofread sub-flow.
// It is pure: takes text input, returns structured review result, no DB access.
type ContentProofread struct {
	gf     *genkitFlow
	g      *genkit.Genkit
	model  genkitai.Model
	logger *slog.Logger
}

// NewContentProofread returns a ContentProofread flow.
func NewContentProofread(g *genkit.Genkit, model genkitai.Model, logger *slog.Logger) *ContentProofread {
	cp := &ContentProofread{
		g:      g,
		model:  model,
		logger: logger,
	}
	cp.gf = genkit.DefineFlow(g, "content-proofread", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in ContentProofreadInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("parsing content-proofread input: %w", err)
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
func (cp *ContentProofread) Name() string { return "content-proofread" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (cp *ContentProofread) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return cp.gf.Run(ctx, input)
}

// run is the typed internal implementation.
func (cp *ContentProofread) run(ctx context.Context, in ContentProofreadInput) (ContentProofreadOutput, error) {
	cp.logger.Info("content-proofread starting", "title", in.Title)

	userPrompt := fmt.Sprintf("Type: %s\nTitle: %s\n\nBody:\n%s", in.ContentType, in.Title, truncateBodyRunes(in.Body))

	result, err := genkit.Run(ctx, "proofread", func() (*ContentProofreadOutput, error) {
		r, resp, err := genkit.GenerateData[ContentProofreadOutput](ctx, cp.g,
			genkitai.WithModel(cp.model),
			genkitai.WithSystem(reviewSystemPrompt),
			genkitai.WithPrompt(userPrompt),
			genkitai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.3),
				MaxOutputTokens: 4096,
			}),
		)
		if err != nil {
			return nil, fmt.Errorf("generating review: %w", err)
		}
		if err := checkFinishReason(resp); err != nil {
			return nil, err
		}
		return r, nil
	})
	if err != nil {
		return ContentProofreadOutput{}, fmt.Errorf("proofreading: %w", err)
	}

	cp.logger.Info("content-proofread complete", "title", in.Title, "level", result.Level)
	return *result, nil
}

// NewMockContentProofread returns a mock Flow that returns canned proofread output.
func NewMockContentProofread() Flow {
	return &mockFlow{
		name: "content-proofread",
		output: ContentProofreadOutput{
			Level:       "auto",
			Notes:       "mock mode",
			Corrections: []string{},
		},
	}
}
