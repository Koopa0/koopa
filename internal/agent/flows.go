package agent

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/core/api"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
)

// pathValidator path validator (allows working directory and user home directory)
var pathValidator *security.PathValidator

func init() {
	// Initialize path validator
	// Allow access to working directory and user home directory
	homeDir, _ := security.GetHomeDir()
	var err error
	pathValidator, err = security.NewPathValidator([]string{homeDir})
	if err != nil {
		// If initialization fails, use empty whitelist (only allow working directory)
		pathValidator, _ = security.NewPathValidator([]string{})
	}
}

// DefineFlows defines all Genkit Flows
// These Flows are designed specifically for Personal AI Assistant to help users complete various daily tasks
// Covers: conversation, content creation, research, productivity, development assistance, and more
func DefineFlows(a *Agent) {
	// ==================== Core General Flows ====================

	// 1. Streaming chat Flow - provides real-time conversational experience
	genkit.DefineStreamingFlow(a.genkitInstance, "chat",
		func(ctx context.Context, userInput string, callback core.StreamCallback[string]) (string, error) {
			finalResponse, err := a.ChatStream(ctx, userInput, func(chunk string) {
				_ = callback(ctx, chunk)
			})
			if err != nil {
				return "", err
			}
			return finalResponse, nil
		})

	// 2. General analysis Flow - unified content analysis entry point
	// Supports analyzing files, logs, documents, URLs and other content types
	type AnalyzeRequest struct {
		Content     string `json:"content"`             // Content (can be file path, URL or direct text)
		ContentType string `json:"content_type"`        // Type: file, log, document, url, text
		Question    string `json:"question,omitempty"`  // Question the user wants to ask (optional)
		Format      string `json:"format,omitempty"`    // Output format: summary, analysis, insights, comparison
		MaxBytes    int    `json:"max_bytes,omitempty"` // Content size limit (0 means unlimited)
	}

	type AnalyzeOutput struct {
		ContentType string   `json:"content_type"`
		Summary     string   `json:"summary,omitempty"`
		Insights    []string `json:"insights,omitempty"`
		KeyPoints   []string `json:"key_points,omitempty"`
		Answer      string   `json:"answer,omitempty"` // 針對 question 的回答
	}

	// AnalyzePromptInput corresponds to the input parameters of analyze.prompt
	type AnalyzePromptInput struct {
		Content     string `json:"content"`
		ContentType string `json:"content_type"`
		Question    string `json:"question"`
	}

	genkit.DefineFlow(a.genkitInstance, "analyze",
		func(ctx context.Context, input AnalyzeRequest) (AnalyzeOutput, error) {
			var content string
			var err error

			// Load content based on content_type
			switch input.ContentType {
			case "file", "log", "document":
				maxBytes := input.MaxBytes
				if maxBytes == 0 {
					maxBytes = 10000 // Default 10KB
				}
				content, err = readFileWithLimit(ctx, input.Content, maxBytes)
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
			analyzePrompt := genkit.LookupPrompt(a.genkitInstance, "analyze")
			if analyzePrompt == nil {
				return AnalyzeOutput{}, fmt.Errorf("analyze prompt not found")
			}

			// Prepare input data
			promptInput := AnalyzePromptInput{
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
			response, err := genkit.Generate(ctx, a.genkitInstance,
				ai.WithModel(a.modelRef),
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

	// ==================== Content Creation Flows ====================

	// 3. Compose email Flow - generates professional emails based on scenarios
	type EmailRequest struct {
		Recipient string `json:"recipient"`          // Recipient (salutation)
		Purpose   string `json:"purpose"`            // Purpose: thanks, request, notification, apology, invitation
		Context   string `json:"context"`            // Background information and specific content
		Tone      string `json:"tone,omitempty"`     // Tone: formal, casual, friendly (default formal)
		Language  string `json:"language,omitempty"` // Language (default Traditional Chinese)
	}

	type EmailOutput struct {
		Subject string `json:"subject"` // Email subject
		Body    string `json:"body"`    // Email content
		Tips    string `json:"tips"`    // Usage tips
	}

	// EmailPromptInput corresponds to the input parameters of email.prompt
	type EmailPromptInput struct {
		Recipient string `json:"recipient"`
		Purpose   string `json:"purpose"`
		Context   string `json:"context"`
		Tone      string `json:"tone"`
		Language  string `json:"language"`
	}

	genkit.DefineFlow(a.genkitInstance, "composeEmail",
		func(ctx context.Context, input EmailRequest) (EmailOutput, error) {
			// Set default values
			tone := input.Tone
			if tone == "" {
				tone = "formal"
			}
			language := input.Language
			if language == "" {
				language = "繁體中文"
			}

			// Use Dotprompt template
			emailPrompt := genkit.LookupPrompt(a.genkitInstance, "composeEmail")
			if emailPrompt == nil {
				return EmailOutput{}, fmt.Errorf("composeEmail prompt not found")
			}

			// Prepare input data
			promptInput := EmailPromptInput{
				Recipient: input.Recipient,
				Purpose:   input.Purpose,
				Context:   input.Context,
				Tone:      tone,
				Language:  language,
			}

			// Render prompt
			actionOpts, err := emailPrompt.Render(ctx, promptInput)
			if err != nil {
				return EmailOutput{}, fmt.Errorf("failed to render prompt: %w", err)
			}

			// Use rendered messages to generate structured output
			response, err := genkit.Generate(ctx, a.genkitInstance,
				ai.WithModel(a.modelRef),
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

	// ==================== Research and Information Flows ====================

	// 4. Topic research Flow - in-depth research on a topic and generates structured report
	type ResearchRequest struct {
		Topic    string   `json:"topic"`              // Research topic
		Focus    []string `json:"focus,omitempty"`    // Focus areas
		Depth    string   `json:"depth,omitempty"`    // Depth: quick, detailed (default detailed)
		Language string   `json:"language,omitempty"` // Language (default Traditional Chinese)
	}

	type ResearchOutput struct {
		Topic     string   `json:"topic"`
		Summary   string   `json:"summary"`    // Summary
		KeyPoints []string `json:"key_points"` // Key points
		Insights  []string `json:"insights"`   // Deep insights
		Questions []string `json:"questions"`  // Extended questions
		NextSteps []string `json:"next_steps"` // Suggested next steps
	}

	// ResearchTopicPromptInput corresponds to the input parameters of research_topic.prompt
	type ResearchTopicPromptInput struct {
		Topic    string   `json:"topic"`
		Focus    []string `json:"focus"`
		Depth    string   `json:"depth"`
		Language string   `json:"language"`
	}

	genkit.DefineFlow(a.genkitInstance, "researchTopic",
		func(ctx context.Context, input ResearchRequest) (ResearchOutput, error) {
			depth := input.Depth
			if depth == "" {
				depth = "detailed"
			}
			language := input.Language
			if language == "" {
				language = "繁體中文"
			}

			// 使用 Dotprompt 模板
			researchPrompt := genkit.LookupPrompt(a.genkitInstance, "researchTopic")
			if researchPrompt == nil {
				return ResearchOutput{}, fmt.Errorf("找不到 researchTopic prompt")
			}

			// 準備輸入資料
			promptInput := ResearchTopicPromptInput{
				Topic:    input.Topic,
				Focus:    input.Focus,
				Depth:    depth,
				Language: language,
			}

			// 渲染 prompt
			actionOpts, err := researchPrompt.Render(ctx, promptInput)
			if err != nil {
				return ResearchOutput{}, fmt.Errorf("渲染 prompt 失敗: %w", err)
			}

			// 使用渲染後的 messages 生成結構化輸出
			response, err := genkit.Generate(ctx, a.genkitInstance,
				ai.WithModel(a.modelRef),
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

	// ==================== Productivity Flows ====================

	// 5. Task planning Flow - breaks down goals into executable task lists
	type TaskPlanRequest struct {
		Goal        string   `json:"goal"`                  // Goal description
		Deadline    string   `json:"deadline,omitempty"`    // Deadline
		Constraints []string `json:"constraints,omitempty"` // Constraints
		Resources   []string `json:"resources,omitempty"`   // Available resources
	}

	type Task struct {
		Title        string   `json:"title"`                  // Task title
		Description  string   `json:"description"`            // Detailed description
		Priority     string   `json:"priority"`               // Priority: high, medium, low
		Duration     string   `json:"duration"`               // Estimated time
		Dependencies []string `json:"dependencies,omitempty"` // Dependent tasks
	}

	type TaskPlanOutput struct {
		Goal        string   `json:"goal"`
		Strategy    string   `json:"strategy"`    // Overall strategy
		Tasks       []Task   `json:"tasks"`       // Task list
		Timeline    string   `json:"timeline"`    // Timeline planning
		Risks       []string `json:"risks"`       // Risk warnings
		Suggestions []string `json:"suggestions"` // Improvement suggestions
	}

	// TaskPlanPromptInput corresponds to the input parameters of task_plan.prompt
	type TaskPlanPromptInput struct {
		Goal        string   `json:"goal"`
		Deadline    string   `json:"deadline"`
		Constraints []string `json:"constraints"`
		Resources   []string `json:"resources"`
	}

	genkit.DefineFlow(a.genkitInstance, "planTasks",
		func(ctx context.Context, input TaskPlanRequest) (TaskPlanOutput, error) {
			// 使用 Dotprompt 模板
			planPrompt := genkit.LookupPrompt(a.genkitInstance, "planTasks")
			if planPrompt == nil {
				return TaskPlanOutput{}, fmt.Errorf("找不到 planTasks prompt")
			}

			// 準備輸入資料
			promptInput := TaskPlanPromptInput(input)

			// 渲染 prompt
			actionOpts, err := planPrompt.Render(ctx, promptInput)
			if err != nil {
				return TaskPlanOutput{}, fmt.Errorf("渲染 prompt 失敗: %w", err)
			}

			// 使用渲染後的 messages 生成結構化輸出
			response, err := genkit.Generate(ctx, a.genkitInstance,
				ai.WithModel(a.modelRef),
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

	// ==================== Development Assistant Flows ====================

	// 6. Code review Flow - reviews code and provides improvement suggestions
	type CodeReviewOutput struct {
		Issues        []string `json:"issues"`
		Suggestions   []string `json:"suggestions"`
		BestPractices []string `json:"best_practices"`
		Rating        string   `json:"rating"`
	}

	// CodeReviewPromptInput corresponds to the input parameters of code_review.prompt
	type CodeReviewPromptInput struct {
		Code string `json:"code"`
	}

	genkit.DefineFlow(a.genkitInstance, "reviewCode",
		func(ctx context.Context, filePath string) (CodeReviewOutput, error) {
			// Read code (using shared function)
			code, err := readFileWithLimit(ctx, filePath, 0) // 0 means unlimited
			if err != nil {
				return CodeReviewOutput{}, err
			}

			// Use Dotprompt template
			reviewPrompt := genkit.LookupPrompt(a.genkitInstance, "reviewCode")
			if reviewPrompt == nil {
				return CodeReviewOutput{}, fmt.Errorf("reviewCode prompt not found")
			}

			// Prepare input data
			promptInput := CodeReviewPromptInput{
				Code: code,
			}

			// Render prompt
			actionOpts, err := reviewPrompt.Render(ctx, promptInput)
			if err != nil {
				return CodeReviewOutput{}, fmt.Errorf("failed to render prompt: %w", err)
			}

			// Use rendered messages to generate structured output
			response, err := genkit.Generate(ctx, a.genkitInstance,
				ai.WithModel(a.modelRef),
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

	// 7. Terminal command suggestion Flow - suggests safe terminal commands based on user intent
	type CommandSuggestion struct {
		Command     string `json:"command"`
		Explanation string `json:"explanation"`
		Safety      string `json:"safety"`
	}

	// CommandSuggestPromptInput corresponds to the input parameters of command_suggest.prompt
	type CommandSuggestPromptInput struct {
		Intent string `json:"intent"`
	}

	genkit.DefineFlow(a.genkitInstance, "suggestCommand",
		func(ctx context.Context, intent string) (CommandSuggestion, error) {
			// Use Dotprompt template
			commandPrompt := genkit.LookupPrompt(a.genkitInstance, "suggestCommand")
			if commandPrompt == nil {
				return CommandSuggestion{}, fmt.Errorf("suggestCommand prompt not found")
			}

			// Prepare input data
			promptInput := CommandSuggestPromptInput{
				Intent: intent,
			}

			// Render prompt
			actionOpts, err := commandPrompt.Render(ctx, promptInput)
			if err != nil {
				return CommandSuggestion{}, fmt.Errorf("failed to render prompt: %w", err)
			}

			// Use rendered messages to generate structured output
			response, err := genkit.Generate(ctx, a.genkitInstance,
				ai.WithModel(a.modelRef),
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

	// 8. Git commit message generation Flow - generates conventional commit messages based on diff
	type GitCommitMessage struct {
		Subject string   `json:"subject"`
		Body    string   `json:"body"`
		Type    string   `json:"type"`
		Files   []string `json:"files"`
	}

	// GenerateCommitMessagePromptInput corresponds to the input parameters of generate_commit_message.prompt
	type GenerateCommitMessagePromptInput struct {
		Diff string `json:"diff"`
	}

	genkit.DefineFlow(a.genkitInstance, "generateCommitMessage",
		func(ctx context.Context, diff string) (GitCommitMessage, error) {
			// Use Dotprompt template
			commitPrompt := genkit.LookupPrompt(a.genkitInstance, "generateCommitMessage")
			if commitPrompt == nil {
				return GitCommitMessage{}, fmt.Errorf("generateCommitMessage prompt not found")
			}

			// Prepare input data
			promptInput := GenerateCommitMessagePromptInput{
				Diff: diff,
			}

			// Render prompt
			actionOpts, err := commitPrompt.Render(ctx, promptInput)
			if err != nil {
				return GitCommitMessage{}, fmt.Errorf("failed to render prompt: %w", err)
			}

			// Use rendered messages to generate structured output
			response, err := genkit.Generate(ctx, a.genkitInstance,
				ai.WithModel(a.modelRef),
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

	// 9. Error diagnosis Flow - diagnoses error messages and provides complete solutions
	type ErrorDiagnosis struct {
		ErrorType  string   `json:"error_type"`
		Causes     []string `json:"causes"`
		Solutions  []string `json:"solutions"`
		Prevention []string `json:"prevention"`
		References []string `json:"references"`
	}

	// ErrorDiagnosePromptInput corresponds to the input parameters of error_diagnose.prompt
	type ErrorDiagnosePromptInput struct {
		ErrorMessage string `json:"error_message"`
	}

	genkit.DefineFlow(a.genkitInstance, "diagnoseError",
		func(ctx context.Context, errorMessage string) (ErrorDiagnosis, error) {
			// Use Dotprompt template
			errorPrompt := genkit.LookupPrompt(a.genkitInstance, "diagnoseError")
			if errorPrompt == nil {
				return ErrorDiagnosis{}, fmt.Errorf("diagnoseError prompt not found")
			}

			// Prepare input data
			promptInput := ErrorDiagnosePromptInput{
				ErrorMessage: errorMessage,
			}

			// Render prompt
			actionOpts, err := errorPrompt.Render(ctx, promptInput)
			if err != nil {
				return ErrorDiagnosis{}, fmt.Errorf("failed to render prompt: %w", err)
			}

			// Use rendered messages to generate structured output
			response, err := genkit.Generate(ctx, a.genkitInstance,
				ai.WithModel(a.modelRef),
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

// GetAllFlows retrieves all defined Flows
func (a *Agent) GetAllFlows() []api.Action {
	return genkit.ListFlows(a.genkitInstance)
}

// readFileWithLimit reads file content with size limit (composable helper function)
// maxBytes: maximum bytes, 0 means unlimited
// For log files: returns last N bytes (tail)
// For regular files: returns first N bytes (head)
func readFileWithLimit(ctx context.Context, filePath string, maxBytes int) (string, error) {
	return genkit.Run(ctx, fmt.Sprintf("read-file-%s", filePath),
		func() (string, error) {
			// Path security validation (prevent path traversal attacks CWE-22)
			safePath, err := pathValidator.ValidatePath(filePath)
			if err != nil {
				return "", fmt.Errorf("path validation failed: %w", err)
			}

			data, err := os.ReadFile(safePath)
			if err != nil {
				return "", fmt.Errorf("unable to read file %s: %w", safePath, err)
			}

			// Unlimited
			if maxBytes <= 0 || len(data) <= maxBytes {
				return string(data), nil
			}

			// Log files take tail (latest content)
			// Determined by filename: containing "log" or ".log" is considered a log file
			isLogFile := containsIgnoreCase(filePath, "log")

			if isLogFile {
				// Take last maxBytes bytes
				return string(data[len(data)-maxBytes:]), nil
			} else {
				// Regular files take first maxBytes bytes
				return string(data[:maxBytes]) + "...", nil
			}
		})
}

// containsIgnoreCase case-insensitive string contains check
func containsIgnoreCase(str, substr string) bool {
	return strings.Contains(strings.ToLower(str), strings.ToLower(substr))
}
