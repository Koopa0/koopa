package flows

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// ============ Types ============

// TaskPlanInput represents input for task planning
type TaskPlanInput struct {
	Goal        string   `json:"goal"`                    
	Context     string   `json:"context,omitempty"`       
	Constraints []string `json:"constraints,omitempty"`   
	Preferences string   `json:"preferences,omitempty"`   
	Language    string   `json:"language,omitempty"`      
}

// TaskPlanOutput represents task planning output
type TaskPlanOutput struct {
	Goal      string   `json:"goal"`
	Tasks     []string `json:"tasks"`
	Timeline  string   `json:"timeline"`
	Priority  []string `json:"priority"`
	Resources []string `json:"resources"`
	RiskItems []string `json:"risk_items"`
}

type taskPlanPromptInput struct {
	Goal        string   `json:"goal"`
	Context     string   `json:"context"`
	Constraints []string `json:"constraints"`
	Preferences string   `json:"preferences"`
	Language    string   `json:"language"`
}

// ============ Flow Definitions ============

// defineProductivityFlows defines productivity-related flows
func defineProductivityFlows(g *genkit.Genkit, modelRef ai.ModelRef) {
	// Task planning flow
	genkit.DefineFlow(g, "planTasks",
		func(ctx context.Context, input TaskPlanInput) (TaskPlanOutput, error) {
			language := input.Language
			if language == "" {
				language = "繁體中文"
			}

			planPrompt := genkit.LookupPrompt(g, "planTasks")
			if planPrompt == nil {
				return TaskPlanOutput{}, fmt.Errorf("planTasks prompt not found")
			}

			promptInput := taskPlanPromptInput{
				Goal:        input.Goal,
				Context:     input.Context,
				Constraints: input.Constraints,
				Preferences: input.Preferences,
				Language:    language,
			}

			actionOpts, err := planPrompt.Render(ctx, promptInput)
			if err != nil {
				return TaskPlanOutput{}, fmt.Errorf("failed to render prompt: %w", err)
			}

			response, err := genkit.Generate(ctx, g,
				ai.WithModel(modelRef),
				ai.WithMessages(actionOpts.Messages...),
				ai.WithOutputType(TaskPlanOutput{}),
			)
			if err != nil {
				return TaskPlanOutput{}, err
			}

			var output TaskPlanOutput
			if err := response.Output(&output); err != nil {
				return TaskPlanOutput{}, err
			}
			output.Goal = input.Goal

			return output, nil
		})
}
