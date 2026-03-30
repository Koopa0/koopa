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

// ProofreadInput is the JSON input for the content-proofread sub-flow.
type ProofreadInput struct {
	ContentType string `json:"content_type"`
	Title       string `json:"title"`
	Body        string `json:"body"`
}

// ProofreadOutput is the JSON output of the content-proofread sub-flow.
type ProofreadOutput struct {
	Level       string   `json:"level"`
	Notes       string   `json:"notes"`
	Corrections []string `json:"corrections"`
}

// Proofread implements the content-proofread sub-flow.
// It is pure: takes text input, returns structured review result, no DB access.
type Proofread struct {
	gf           *GenkitFlow
	g            *genkit.Genkit
	model        genkitai.Model
	systemPrompt string
	logger       *slog.Logger
}

// NewProofread returns a Proofread flow.
func NewProofread(g *genkit.Genkit, model genkitai.Model, systemPrompt string, logger *slog.Logger) *Proofread {
	cp := &Proofread{
		g:            g,
		model:        model,
		systemPrompt: systemPrompt,
		logger:       logger,
	}
	cp.gf = genkit.DefineFlow(g, "content-proofread", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in ProofreadInput
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
func (cp *Proofread) Name() string { return "content-proofread" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (cp *Proofread) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return cp.gf.Run(ctx, input)
}

// run is the typed internal implementation.
func (cp *Proofread) run(ctx context.Context, in ProofreadInput) (ProofreadOutput, error) {
	cp.logger.Info("content-proofread starting", "title", in.Title)

	userPrompt := fmt.Sprintf("Type: %s\nTitle: %s\n\nBody:\n%s", in.ContentType, in.Title, TruncateBodyRunes(in.Body))

	result, err := genkit.Run(ctx, "proofread", func() (*ProofreadOutput, error) {
		r, resp, err := genkit.GenerateData[ProofreadOutput](ctx, cp.g,
			genkitai.WithModel(cp.model),
			genkitai.WithSystem(cp.systemPrompt),
			genkitai.WithPrompt(userPrompt),
			genkitai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.3),
				MaxOutputTokens: 4096,
			}),
		)
		if err != nil {
			return nil, fmt.Errorf("generating review: %w", err)
		}
		if err := CheckFinishReason(resp); err != nil {
			return nil, err
		}
		return r, nil
	})
	if err != nil {
		return ProofreadOutput{}, fmt.Errorf("proofreading: %w", err)
	}

	cp.logger.Info("content-proofread complete", "title", in.Title, "level", result.Level)
	return *result, nil
}
