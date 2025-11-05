package flows

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// ============ Types ============

// EmailInput represents input for email composition
type EmailInput struct {
	Recipient string `json:"recipient"`
	Purpose   string `json:"purpose"`
	Context   string `json:"context"`
	Tone      string `json:"tone,omitempty"`
	Language  string `json:"language,omitempty"`
}

// EmailOutput represents email composition output
type EmailOutput struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
	Tips    string `json:"tips"`
}

type emailPromptInput struct {
	Recipient string `json:"recipient"`
	Purpose   string `json:"purpose"`
	Context   string `json:"context"`
	Tone      string `json:"tone"`
	Language  string `json:"language"`
}

// ResearchInput represents input for topic research
type ResearchInput struct {
	Topic    string   `json:"topic"`
	Focus    []string `json:"focus,omitempty"`
	Depth    string   `json:"depth,omitempty"`
	Language string   `json:"language,omitempty"`
}

// ResearchOutput represents research output
type ResearchOutput struct {
	Topic     string   `json:"topic"`
	Summary   string   `json:"summary"`
	KeyPoints []string `json:"key_points"`
	Insights  []string `json:"insights"`
	Questions []string `json:"questions"`
	NextSteps []string `json:"next_steps"`
}

type researchTopicPromptInput struct {
	Topic    string   `json:"topic"`
	Focus    []string `json:"focus"`
	Depth    string   `json:"depth"`
	Language string   `json:"language"`
}

// ============ Flow Definitions ============

// defineContentFlows defines content creation flows
func defineContentFlows(g *genkit.Genkit, modelRef ai.ModelRef) {
	// 1. Compose email flow
	genkit.DefineFlow(g, "composeEmail",
		func(ctx context.Context, input EmailInput) (EmailOutput, error) {
			tone := input.Tone
			if tone == "" {
				tone = "formal"
			}
			language := input.Language
			if language == "" {
				language = "繁體中文"
			}

			emailPrompt := genkit.LookupPrompt(g, "composeEmail")
			if emailPrompt == nil {
				return EmailOutput{}, fmt.Errorf("composeEmail prompt not found")
			}

			promptInput := emailPromptInput{
				Recipient: input.Recipient,
				Purpose:   input.Purpose,
				Context:   input.Context,
				Tone:      tone,
				Language:  language,
			}

			actionOpts, err := emailPrompt.Render(ctx, promptInput)
			if err != nil {
				return EmailOutput{}, fmt.Errorf("failed to render prompt: %w", err)
			}

			response, err := genkit.Generate(ctx, g,
				ai.WithModel(modelRef),
				ai.WithMessages(actionOpts.Messages...),
				ai.WithOutputType(EmailOutput{}),
			)
			if err != nil {
				return EmailOutput{}, err
			}

			var output EmailOutput
			if err := response.Output(&output); err != nil {
				return EmailOutput{}, err
			}

			return output, nil
		})

	// 2. Research topic flow
	genkit.DefineFlow(g, "researchTopic",
		func(ctx context.Context, input ResearchInput) (ResearchOutput, error) {
			depth := input.Depth
			if depth == "" {
				depth = "detailed"
			}
			language := input.Language
			if language == "" {
				language = "繁體中文"
			}

			researchPrompt := genkit.LookupPrompt(g, "researchTopic")
			if researchPrompt == nil {
				return ResearchOutput{}, fmt.Errorf("researchTopic prompt not found")
			}

			promptInput := researchTopicPromptInput{
				Topic:    input.Topic,
				Focus:    input.Focus,
				Depth:    depth,
				Language: language,
			}

			actionOpts, err := researchPrompt.Render(ctx, promptInput)
			if err != nil {
				return ResearchOutput{}, fmt.Errorf("failed to render prompt: %w", err)
			}

			response, err := genkit.Generate(ctx, g,
				ai.WithModel(modelRef),
				ai.WithMessages(actionOpts.Messages...),
				ai.WithOutputType(ResearchOutput{}),
			)
			if err != nil {
				return ResearchOutput{}, err
			}

			var output ResearchOutput
			if err := response.Output(&output); err != nil {
				return ResearchOutput{}, err
			}
			output.Topic = input.Topic

			return output, nil
		})
}
