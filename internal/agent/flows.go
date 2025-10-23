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
)

// DefineFlows 定義所有 Genkit Flows
// 這些 Flows 專為 Personal AI Assistant 設計，協助用戶完成各種日常任務
// 涵蓋：對話、內容創作、研究、生產力、開發輔助等多個領域
func DefineFlows(a *Agent) {
	// ==================== 核心通用 Flows ====================

	// 1. 流式對話 Flow - 提供即時回應的對話體驗
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

	// 2. 通用分析 Flow - 統一的內容分析入口
	// 支援分析檔案、日誌、文件、URL 等各種內容類型
	type AnalyzeRequest struct {
		Content     string `json:"content"`             // 內容（可以是檔案路徑、URL 或直接文字）
		ContentType string `json:"content_type"`        // 類型: file, log, document, url, text
		Question    string `json:"question,omitempty"`  // 用戶想問的問題（可選）
		Format      string `json:"format,omitempty"`    // 輸出格式: summary, analysis, insights, comparison
		MaxBytes    int    `json:"max_bytes,omitempty"` // 內容大小限制（0 表示無限制）
	}

	type AnalyzeOutput struct {
		ContentType string   `json:"content_type"`
		Summary     string   `json:"summary,omitempty"`
		Insights    []string `json:"insights,omitempty"`
		KeyPoints   []string `json:"key_points,omitempty"`
		Answer      string   `json:"answer,omitempty"` // 針對 question 的回答
	}

	// AnalyzePromptInput 對應 analyze.prompt 的輸入參數
	type AnalyzePromptInput struct {
		Content     string `json:"content"`
		ContentType string `json:"content_type"`
		Question    string `json:"question"`
	}

	genkit.DefineFlow(a.genkitInstance, "analyze",
		func(ctx context.Context, input AnalyzeRequest) (AnalyzeOutput, error) {
			var content string
			var err error

			// 根據 content_type 載入內容
			switch input.ContentType {
			case "file", "log", "document":
				maxBytes := input.MaxBytes
				if maxBytes == 0 {
					maxBytes = 10000 // 預設 10KB
				}
				content, err = readFileWithLimit(ctx, input.Content, maxBytes)
				if err != nil {
					return AnalyzeOutput{}, fmt.Errorf("無法讀取檔案: %w", err)
				}
			case "url":
				// TODO: 未來可以加入網頁抓取功能
				return AnalyzeOutput{}, fmt.Errorf("URL 分析功能尚未實作")
			case "text":
				content = input.Content
			default:
				return AnalyzeOutput{}, fmt.Errorf("不支援的內容類型: %s", input.ContentType)
			}

			// 使用 Dotprompt 模板（含 Prompt Injection 防護）
			analyzePrompt := genkit.LookupPrompt(a.genkitInstance, "analyze")
			if analyzePrompt == nil {
				return AnalyzeOutput{}, fmt.Errorf("找不到 analyze prompt")
			}

			// 準備輸入資料（強型別）
			promptInput := AnalyzePromptInput{
				Content:     content,
				ContentType: input.ContentType,
				Question:    input.Question,
			}

			// 渲染 prompt
			actionOpts, err := analyzePrompt.Render(ctx, promptInput)
			if err != nil {
				return AnalyzeOutput{}, fmt.Errorf("渲染 prompt 失敗: %w", err)
			}

			// 使用渲染後的 messages 生成結構化輸出
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

	// ==================== 內容創作 Flows ====================

	// 3. 撰寫郵件 Flow - 根據場景生成專業郵件
	type EmailRequest struct {
		Recipient string `json:"recipient"`          // 收件人（稱呼）
		Purpose   string `json:"purpose"`            // 目的: thanks, request, notification, apology, invitation
		Context   string `json:"context"`            // 背景資訊和具體內容
		Tone      string `json:"tone,omitempty"`     // 語氣: formal, casual, friendly（預設 formal）
		Language  string `json:"language,omitempty"` // 語言（預設繁體中文）
	}

	type EmailOutput struct {
		Subject string `json:"subject"` // 郵件主旨
		Body    string `json:"body"`    // 郵件內容
		Tips    string `json:"tips"`    // 使用建議
	}

	// EmailPromptInput 對應 email.prompt 的輸入參數
	type EmailPromptInput struct {
		Recipient string `json:"recipient"`
		Purpose   string `json:"purpose"`
		Context   string `json:"context"`
		Tone      string `json:"tone"`
		Language  string `json:"language"`
	}

	genkit.DefineFlow(a.genkitInstance, "composeEmail",
		func(ctx context.Context, input EmailRequest) (EmailOutput, error) {
			// 設定預設值
			tone := input.Tone
			if tone == "" {
				tone = "formal"
			}
			language := input.Language
			if language == "" {
				language = "繁體中文"
			}

			// 使用 Dotprompt 模板
			emailPrompt := genkit.LookupPrompt(a.genkitInstance, "composeEmail")
			if emailPrompt == nil {
				return EmailOutput{}, fmt.Errorf("找不到 composeEmail prompt")
			}

			// 準備輸入資料（強型別）
			promptInput := EmailPromptInput{
				Recipient: input.Recipient,
				Purpose:   input.Purpose,
				Context:   input.Context,
				Tone:      tone,
				Language:  language,
			}

			// 渲染 prompt
			actionOpts, err := emailPrompt.Render(ctx, promptInput)
			if err != nil {
				return EmailOutput{}, fmt.Errorf("渲染 prompt 失敗: %w", err)
			}

			// 使用渲染後的 messages 生成結構化輸出
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

	// ==================== 研究與資訊 Flows ====================

	// 4. 主題研究 Flow - 深入研究一個主題並產生結構化報告
	type ResearchRequest struct {
		Topic    string   `json:"topic"`              // 研究主題
		Focus    []string `json:"focus,omitempty"`    // 重點關注面向
		Depth    string   `json:"depth,omitempty"`    // 深度: quick, detailed（預設 detailed）
		Language string   `json:"language,omitempty"` // 語言（預設繁體中文）
	}

	type ResearchOutput struct {
		Topic     string   `json:"topic"`
		Summary   string   `json:"summary"`    // 總結
		KeyPoints []string `json:"key_points"` // 關鍵要點
		Insights  []string `json:"insights"`   // 深入見解
		Questions []string `json:"questions"`  // 延伸問題
		NextSteps []string `json:"next_steps"` // 建議後續步驟
	}

	// ResearchTopicPromptInput 對應 research_topic.prompt 的輸入參數
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

			// 準備輸入資料（強型別）
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

	// ==================== 生產力 Flows ====================

	// 5. 任務規劃 Flow - 將目標拆解成可執行的任務清單
	type TaskPlanRequest struct {
		Goal        string   `json:"goal"`                  // 目標描述
		Deadline    string   `json:"deadline,omitempty"`    // 截止時間
		Constraints []string `json:"constraints,omitempty"` // 限制條件
		Resources   []string `json:"resources,omitempty"`   // 可用資源
	}

	type Task struct {
		Title        string   `json:"title"`                  // 任務標題
		Description  string   `json:"description"`            // 詳細說明
		Priority     string   `json:"priority"`               // 優先級: high, medium, low
		Duration     string   `json:"duration"`               // 預估時間
		Dependencies []string `json:"dependencies,omitempty"` // 依賴的任務
	}

	type TaskPlanOutput struct {
		Goal        string   `json:"goal"`
		Strategy    string   `json:"strategy"`    // 整體策略
		Tasks       []Task   `json:"tasks"`       // 任務清單
		Timeline    string   `json:"timeline"`    // 時間規劃
		Risks       []string `json:"risks"`       // 風險提醒
		Suggestions []string `json:"suggestions"` // 改進建議
	}

	// TaskPlanPromptInput 對應 task_plan.prompt 的輸入參數
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

			// 準備輸入資料（強型別）
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

	// ==================== 開發輔助 Flows ====================

	// 6. 程式碼審查 Flow - 審查程式碼並提供改進建議
	type CodeReviewOutput struct {
		Issues        []string `json:"issues"`
		Suggestions   []string `json:"suggestions"`
		BestPractices []string `json:"best_practices"`
		Rating        string   `json:"rating"`
	}

	// CodeReviewPromptInput 對應 code_review.prompt 的輸入參數
	type CodeReviewPromptInput struct {
		Code string `json:"code"`
	}

	genkit.DefineFlow(a.genkitInstance, "reviewCode",
		func(ctx context.Context, filePath string) (CodeReviewOutput, error) {
			// 讀取程式碼（使用共用函數）
			code, err := readFileWithLimit(ctx, filePath, 0) // 0 表示無限制
			if err != nil {
				return CodeReviewOutput{}, err
			}

			// 使用 Dotprompt 模板
			reviewPrompt := genkit.LookupPrompt(a.genkitInstance, "reviewCode")
			if reviewPrompt == nil {
				return CodeReviewOutput{}, fmt.Errorf("找不到 reviewCode prompt")
			}

			// 準備輸入資料（強型別）
			promptInput := CodeReviewPromptInput{
				Code: code,
			}

			// 渲染 prompt
			actionOpts, err := reviewPrompt.Render(ctx, promptInput)
			if err != nil {
				return CodeReviewOutput{}, fmt.Errorf("渲染 prompt 失敗: %w", err)
			}

			// 使用渲染後的 messages 生成結構化輸出
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

	// 7. 終端命令建議 Flow - 根據用戶意圖建議安全的終端命令
	type CommandSuggestion struct {
		Command     string `json:"command"`
		Explanation string `json:"explanation"`
		Safety      string `json:"safety"`
	}

	// CommandSuggestPromptInput 對應 command_suggest.prompt 的輸入參數
	type CommandSuggestPromptInput struct {
		Intent string `json:"intent"`
	}

	genkit.DefineFlow(a.genkitInstance, "suggestCommand",
		func(ctx context.Context, intent string) (CommandSuggestion, error) {
			// 使用 Dotprompt 模板
			commandPrompt := genkit.LookupPrompt(a.genkitInstance, "suggestCommand")
			if commandPrompt == nil {
				return CommandSuggestion{}, fmt.Errorf("找不到 suggestCommand prompt")
			}

			// 準備輸入資料（強型別）
			promptInput := CommandSuggestPromptInput{
				Intent: intent,
			}

			// 渲染 prompt
			actionOpts, err := commandPrompt.Render(ctx, promptInput)
			if err != nil {
				return CommandSuggestion{}, fmt.Errorf("渲染 prompt 失敗: %w", err)
			}

			// 使用渲染後的 messages 生成結構化輸出
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

	// 8. Git 提交訊息生成 Flow - 根據 diff 生成符合慣例的提交訊息
	type GitCommitMessage struct {
		Subject string   `json:"subject"`
		Body    string   `json:"body"`
		Type    string   `json:"type"`
		Files   []string `json:"files"`
	}

	// GenerateCommitMessagePromptInput 對應 generate_commit_message.prompt 的輸入參數
	type GenerateCommitMessagePromptInput struct {
		Diff string `json:"diff"`
	}

	genkit.DefineFlow(a.genkitInstance, "generateCommitMessage",
		func(ctx context.Context, diff string) (GitCommitMessage, error) {
			// 使用 Dotprompt 模板
			commitPrompt := genkit.LookupPrompt(a.genkitInstance, "generateCommitMessage")
			if commitPrompt == nil {
				return GitCommitMessage{}, fmt.Errorf("找不到 generateCommitMessage prompt")
			}

			// 準備輸入資料（強型別）
			promptInput := GenerateCommitMessagePromptInput{
				Diff: diff,
			}

			// 渲染 prompt
			actionOpts, err := commitPrompt.Render(ctx, promptInput)
			if err != nil {
				return GitCommitMessage{}, fmt.Errorf("渲染 prompt 失敗: %w", err)
			}

			// 使用渲染後的 messages 生成結構化輸出
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

	// 9. 錯誤診斷 Flow - 診斷錯誤訊息並提供完整解決方案
	type ErrorDiagnosis struct {
		ErrorType  string   `json:"error_type"`
		Causes     []string `json:"causes"`
		Solutions  []string `json:"solutions"`
		Prevention []string `json:"prevention"`
		References []string `json:"references"`
	}

	// ErrorDiagnosePromptInput 對應 error_diagnose.prompt 的輸入參數
	type ErrorDiagnosePromptInput struct {
		ErrorMessage string `json:"error_message"`
	}

	genkit.DefineFlow(a.genkitInstance, "diagnoseError",
		func(ctx context.Context, errorMessage string) (ErrorDiagnosis, error) {
			// 使用 Dotprompt 模板
			errorPrompt := genkit.LookupPrompt(a.genkitInstance, "diagnoseError")
			if errorPrompt == nil {
				return ErrorDiagnosis{}, fmt.Errorf("找不到 diagnoseError prompt")
			}

			// 準備輸入資料（強型別）
			promptInput := ErrorDiagnosePromptInput{
				ErrorMessage: errorMessage,
			}

			// 渲染 prompt
			actionOpts, err := errorPrompt.Render(ctx, promptInput)
			if err != nil {
				return ErrorDiagnosis{}, fmt.Errorf("渲染 prompt 失敗: %w", err)
			}

			// 使用渲染後的 messages 生成結構化輸出
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

// GetAllFlows 獲取所有已定義的 Flows
func (a *Agent) GetAllFlows() []api.Action {
	return genkit.ListFlows(a.genkitInstance)
}

// readFileWithLimit 讀取檔案內容並限制大小（可組合的輔助函數）
// maxBytes: 最大字節數，0 表示無限制
// 對於日誌檔案：返回最後 N 個字節（尾部）
// 對於一般檔案：返回前 N 個字節（開頭）
func readFileWithLimit(ctx context.Context, filePath string, maxBytes int) (string, error) {
	return genkit.Run(ctx, fmt.Sprintf("read-file-%s", filePath),
		func() (string, error) {
			data, err := os.ReadFile(filePath)
			if err != nil {
				return "", fmt.Errorf("無法讀取檔案 %s: %w", filePath, err)
			}

			// 無限制
			if maxBytes <= 0 || len(data) <= maxBytes {
				return string(data), nil
			}

			// 日誌檔案取尾部（最新的內容）
			// 通過檔案名判斷：包含 "log" 或 ".log" 的視為日誌
			isLogFile := containsIgnoreCase(filePath, "log")

			if isLogFile {
				// 取最後 maxBytes 字節
				return string(data[len(data)-maxBytes:]), nil
			} else {
				// 一般檔案取前 maxBytes 字節
				return string(data[:maxBytes]) + "...", nil
			}
		})
}

// containsIgnoreCase 不區分大小寫的字串包含檢查
func containsIgnoreCase(str, substr string) bool {
	return strings.Contains(strings.ToLower(str), strings.ToLower(substr))
}
