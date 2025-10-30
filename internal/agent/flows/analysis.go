package flows

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
)

// ============ Types ============

// AnalyzeInput represents input for content analysis
type AnalyzeInput struct {
	Content     string `json:"content"`             // Content (can be file path, URL or direct text)
	ContentType string `json:"content_type"`        // Type: file, log, document, url, text
	Question    string `json:"question,omitempty"`  // Question the user wants to ask (optional)
	Format      string `json:"format,omitempty"`    // Output format: summary, analysis, insights, comparison
	MaxBytes    int    `json:"max_bytes,omitempty"` // Content size limit (0 means unlimited)
}

// AnalyzeOutput represents output from content analysis
type AnalyzeOutput struct {
	ContentType string   `json:"content_type"`
	Summary     string   `json:"summary,omitempty"`
	Insights    []string `json:"insights,omitempty"`
	KeyPoints   []string `json:"key_points,omitempty"`
	Answer      string   `json:"answer,omitempty"` // Answer to the question
}

// analyzePromptInput corresponds to the input parameters of analyze.prompt
type analyzePromptInput struct {
	Content     string `json:"content"`
	ContentType string `json:"content_type"`
	Question    string `json:"question"`
}

// ErrorDiagnosis represents error diagnostic output
type ErrorDiagnosis struct {
	ErrorType  string   `json:"error_type"`
	Causes     []string `json:"causes"`
	Solutions  []string `json:"solutions"`
	Prevention []string `json:"prevention"`
	References []string `json:"references"`
}

// errorDiagnosePromptInput corresponds to the input parameters of diagnoseError.prompt
type errorDiagnosePromptInput struct {
	ErrorMessage string `json:"error_message"`
}

// ============ Flow Definitions ============

// defineAnalysisFlows defines analysis-related flows
// pathValidator is passed as parameter and captured by closures (Go best practice)
func defineAnalysisFlows(g *genkit.Genkit, modelRef ai.ModelRef, pathValidator *security.PathValidator) {
	// 1. General analysis Flow - unified content analysis entry point
	genkit.DefineFlow(g, "analyze",
		func(ctx context.Context, input AnalyzeInput) (AnalyzeOutput, error) {
			var content string
			var err error

			// Load content based on content_type
			switch input.ContentType {
			case "file", "log", "document":
				maxBytes := input.MaxBytes
				if maxBytes == 0 {
					maxBytes = 10000 // Default 10KB
				}
				content, err = readFileWithLimit(ctx, pathValidator, input.Content, maxBytes)
				if err != nil {
					return AnalyzeOutput{}, fmt.Errorf("unable to read file: %w", err)
				}
			case "url":
				// TODO: Can add web scraping functionality in the future
				return AnalyzeOutput{}, fmt.Errorf("URL analysis functionality not yet implemented")
			case "text":
				content = input.Content
			default:
				return AnalyzeOutput{}, fmt.Errorf("unsupported content type: %s", input.ContentType)
			}

			// Use Dotprompt template (includes Prompt Injection protection)
			analyzePrompt := genkit.LookupPrompt(g, "analyze")
			if analyzePrompt == nil {
				return AnalyzeOutput{}, fmt.Errorf("analyze prompt not found")
			}

			// Prepare input data
			promptInput := analyzePromptInput{
				Content:     content,
				ContentType: input.ContentType,
				Question:    input.Question,
			}

			// Render prompt
			actionOpts, err := analyzePrompt.Render(ctx, promptInput)
			if err != nil {
				return AnalyzeOutput{}, fmt.Errorf("failed to render prompt: %w", err)
			}

			// Use rendered messages to generate structured output
			response, err := genkit.Generate(ctx, g,
				ai.WithModel(modelRef),
				ai.WithMessages(actionOpts.Messages...),
				ai.WithOutputType(AnalyzeOutput{}),
			)
			if err != nil {
				return AnalyzeOutput{}, err
			}

			var output AnalyzeOutput
			if err := response.Output(&output); err != nil {
				return AnalyzeOutput{}, err
			}
			output.ContentType = input.ContentType

			return output, nil
		})

	// 2. Error diagnosis Flow
	genkit.DefineFlow(g, "diagnoseError",
		func(ctx context.Context, errorMessage string) (ErrorDiagnosis, error) {
			// Use Dotprompt template
			errorPrompt := genkit.LookupPrompt(g, "diagnoseError")
			if errorPrompt == nil {
				return ErrorDiagnosis{}, fmt.Errorf("diagnoseError prompt not found")
			}

			// Prepare input data
			promptInput := errorDiagnosePromptInput{
				ErrorMessage: errorMessage,
			}

			// Render prompt
			actionOpts, err := errorPrompt.Render(ctx, promptInput)
			if err != nil {
				return ErrorDiagnosis{}, fmt.Errorf("failed to render prompt: %w", err)
			}

			// Use rendered messages to generate structured output
			response, err := genkit.Generate(ctx, g,
				ai.WithModel(modelRef),
				ai.WithMessages(actionOpts.Messages...),
				ai.WithOutputType(ErrorDiagnosis{}),
			)
			if err != nil {
				return ErrorDiagnosis{}, err
			}

			var output ErrorDiagnosis
			if err := response.Output(&output); err != nil {
				return ErrorDiagnosis{}, err
			}

			return output, nil
		})
}
