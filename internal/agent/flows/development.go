package flows

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
)

// ============ Types ============

// CodeReviewOutput represents code review output
type CodeReviewOutput struct {
	Issues        []string `json:"issues"`
	Suggestions   []string `json:"suggestions"`
	BestPractices []string `json:"best_practices"`
	Rating        string   `json:"rating"`
}

type codeReviewPromptInput struct {
	Code string `json:"code"`
}

// CommandSuggestion represents command suggestion output
type CommandSuggestion struct {
	Command     string `json:"command"`
	Explanation string `json:"explanation"`
	Safety      string `json:"safety"`
}

type commandSuggestPromptInput struct {
	Intent string `json:"intent"`
}

// GitCommitMessage represents git commit message output
type GitCommitMessage struct {
	Subject string   `json:"subject"`
	Body    string   `json:"body"`
	Type    string   `json:"type"`
	Files   []string `json:"files"`
}

type generateCommitMessagePromptInput struct {
	Diff string `json:"diff"`
}

// ============ Flow Definitions ============

// defineDevelopmentFlows defines development-related flows
// pathValidator is passed as parameter and captured by closures (Go best practice)
func defineDevelopmentFlows(g *genkit.Genkit, modelRef ai.ModelRef, pathValidator *security.PathValidator) {
	// 1. Code review flow
	genkit.DefineFlow(g, "reviewCode",
		func(ctx context.Context, filePath string) (CodeReviewOutput, error) {
			code, err := readFileWithLimit(ctx, pathValidator, filePath, 0)
			if err != nil {
				return CodeReviewOutput{}, err
			}

			reviewPrompt := genkit.LookupPrompt(g, "reviewCode")
			if reviewPrompt == nil {
				return CodeReviewOutput{}, fmt.Errorf("reviewCode prompt not found")
			}

			promptInput := codeReviewPromptInput{Code: code}
			actionOpts, err := reviewPrompt.Render(ctx, promptInput)
			if err != nil {
				return CodeReviewOutput{}, fmt.Errorf("failed to render prompt: %w", err)
			}

			response, err := genkit.Generate(ctx, g,
				ai.WithModel(modelRef),
				ai.WithMessages(actionOpts.Messages...),
				ai.WithOutputType(CodeReviewOutput{}),
			)
			if err != nil {
				return CodeReviewOutput{}, err
			}

			var output CodeReviewOutput
			if err := response.Output(&output); err != nil {
				return CodeReviewOutput{}, err
			}
			return output, nil
		})

	// 2. Command suggestion flow
	genkit.DefineFlow(g, "suggestCommand",
		func(ctx context.Context, intent string) (CommandSuggestion, error) {
			commandPrompt := genkit.LookupPrompt(g, "suggestCommand")
			if commandPrompt == nil {
				return CommandSuggestion{}, fmt.Errorf("suggestCommand prompt not found")
			}

			promptInput := commandSuggestPromptInput{Intent: intent}
			actionOpts, err := commandPrompt.Render(ctx, promptInput)
			if err != nil {
				return CommandSuggestion{}, fmt.Errorf("failed to render prompt: %w", err)
			}

			response, err := genkit.Generate(ctx, g,
				ai.WithModel(modelRef),
				ai.WithMessages(actionOpts.Messages...),
				ai.WithOutputType(CommandSuggestion{}),
			)
			if err != nil {
				return CommandSuggestion{}, err
			}

			var output CommandSuggestion
			if err := response.Output(&output); err != nil {
				return CommandSuggestion{}, err
			}
			return output, nil
		})

	// 3. Generate commit message flow
	genkit.DefineFlow(g, "generateCommitMessage",
		func(ctx context.Context, diff string) (GitCommitMessage, error) {
			commitPrompt := genkit.LookupPrompt(g, "generateCommitMessage")
			if commitPrompt == nil {
				return GitCommitMessage{}, fmt.Errorf("generateCommitMessage prompt not found")
			}

			promptInput := generateCommitMessagePromptInput{Diff: diff}
			actionOpts, err := commitPrompt.Render(ctx, promptInput)
			if err != nil {
				return GitCommitMessage{}, fmt.Errorf("failed to render prompt: %w", err)
			}

			response, err := genkit.Generate(ctx, g,
				ai.WithModel(modelRef),
				ai.WithMessages(actionOpts.Messages...),
				ai.WithOutputType(GitCommitMessage{}),
			)
			if err != nil {
				return GitCommitMessage{}, err
			}

			var output GitCommitMessage
			if err := response.Output(&output); err != nil {
				return GitCommitMessage{}, err
			}
			return output, nil
		})
}
