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
// 這些 Flows 專為終端 AI 助理設計，協助用戶完成命令列環境中的實際工作
func DefineFlows(a *Agent) {
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

	// 2. 檔案分析 Flow - 分析檔案內容並提供見解
	type FileAnalysisInput struct {
		FilePath string `json:"file_path"`
		Question string `json:"question,omitempty"`
	}

	type FileAnalysisOutput struct {
		FilePath string `json:"file_path"`
		Summary  string `json:"summary"`
		Insights string `json:"insights"`
	}

	genkit.DefineFlow(a.genkitInstance, "analyzeFile",
		func(ctx context.Context, input FileAnalysisInput) (FileAnalysisOutput, error) {
			// 讀取檔案內容（使用共用函數）
			content, err := readFileWithLimit(ctx, input.FilePath, 0) // 0 表示無限制
			if err != nil {
				return FileAnalysisOutput{}, err
			}

			// 構建提示詞
			prompt := "請分析以下檔案內容並提供摘要和見解：\n\n" + content
			if input.Question != "" {
				prompt += "\n\n特別關注：" + input.Question
			}

			response, err := a.AskWithStructuredOutput(ctx, prompt, FileAnalysisOutput{})
			if err != nil {
				return FileAnalysisOutput{}, err
			}

			var output FileAnalysisOutput
			if err := response.Output(&output); err != nil {
				return FileAnalysisOutput{}, err
			}
			output.FilePath = input.FilePath

			return output, nil
		})

	// 3. 程式碼審查 Flow - 審查程式碼並提供改進建議
	type CodeReviewOutput struct {
		Issues        []string `json:"issues"`
		Suggestions   []string `json:"suggestions"`
		BestPractices []string `json:"best_practices"`
		Rating        string   `json:"rating"`
	}

	genkit.DefineFlow(a.genkitInstance, "reviewCode",
		func(ctx context.Context, filePath string) (CodeReviewOutput, error) {
			// 讀取程式碼（使用共用函數）
			code, err := readFileWithLimit(ctx, filePath, 0) // 0 表示無限制
			if err != nil {
				return CodeReviewOutput{}, err
			}

			response, err := a.AskWithStructuredOutput(ctx,
				"請審查以下程式碼，找出潛在問題、提供改進建議和最佳實踐建議：\n\n"+code,
				CodeReviewOutput{})
			if err != nil {
				return CodeReviewOutput{}, err
			}

			var output CodeReviewOutput
			if err := response.Output(&output); err != nil {
				return CodeReviewOutput{}, err
			}

			return output, nil
		})

	// 4. 日誌分析 Flow - 分析日誌檔案找出錯誤和異常
	type LogAnalysisOutput struct {
		Errors      []string `json:"errors"`
		Warnings    []string `json:"warnings"`
		Patterns    []string `json:"patterns"`
		Suggestions []string `json:"suggestions"`
	}

	genkit.DefineFlow(a.genkitInstance, "analyzeLogs",
		func(ctx context.Context, logPath string) (LogAnalysisOutput, error) {
			// 讀取日誌（限制大小，取最後 10KB）
			logs, err := readFileWithLimit(ctx, logPath, 10000)
			if err != nil {
				return LogAnalysisOutput{}, err
			}

			response, err := a.AskWithStructuredOutput(ctx,
				"請分析以下日誌，找出錯誤、警告、異常模式並提供建議：\n\n"+logs,
				LogAnalysisOutput{})
			if err != nil {
				return LogAnalysisOutput{}, err
			}

			var output LogAnalysisOutput
			if err := response.Output(&output); err != nil {
				return LogAnalysisOutput{}, err
			}

			return output, nil
		})

	// 5. 文件摘要 Flow - 快速總結文件重點
	genkit.DefineFlow(a.genkitInstance, "summarizeDocument",
		func(ctx context.Context, filePath string) (string, error) {
			// 讀取文件（限制大小，取前 5KB）
			content, err := readFileWithLimit(ctx, filePath, 5000)
			if err != nil {
				return "", err
			}

			response, err := genkit.Generate(ctx, a.genkitInstance,
				ai.WithModel(a.modelRef),
				ai.WithMessages(
					a.systemMessage,
					ai.NewUserMessage(ai.NewTextPart("請用繁體中文總結以下文件的重點：\n\n"+content)),
				),
			)
			if err != nil {
				return "", err
			}

			return response.Text(), nil
		})

	// 6. 命令建議 Flow - 根據用戶意圖建議終端命令
	type CommandSuggestion struct {
		Command     string `json:"command"`
		Explanation string `json:"explanation"`
		Safety      string `json:"safety"`
	}

	genkit.DefineFlow(a.genkitInstance, "suggestCommand",
		func(ctx context.Context, intent string) (CommandSuggestion, error) {
			response, err := a.AskWithStructuredOutput(ctx,
				"用戶想要："+intent+"\n請建議適當的終端命令，包含解釋和安全提醒。",
				CommandSuggestion{})
			if err != nil {
				return CommandSuggestion{}, err
			}

			var output CommandSuggestion
			if err := response.Output(&output); err != nil {
				return CommandSuggestion{}, err
			}

			return output, nil
		})

	// 7. Git 提交訊息生成 Flow - 根據 diff 生成提交訊息
	type GitCommitMessage struct {
		Subject string   `json:"subject"`
		Body    string   `json:"body"`
		Type    string   `json:"type"`
		Files   []string `json:"files"`
	}

	genkit.DefineFlow(a.genkitInstance, "generateCommitMessage",
		func(ctx context.Context, diff string) (GitCommitMessage, error) {
			response, err := a.AskWithStructuredOutput(ctx,
				"根據以下 git diff 生成合適的提交訊息（使用繁體中文）：\n\n"+diff,
				GitCommitMessage{})
			if err != nil {
				return GitCommitMessage{}, err
			}

			var output GitCommitMessage
			if err := response.Output(&output); err != nil {
				return GitCommitMessage{}, err
			}

			return output, nil
		})

	// 8. 錯誤診斷 Flow - 診斷錯誤訊息並提供解決方案
	type ErrorDiagnosis struct {
		ErrorType   string   `json:"error_type"`
		Causes      []string `json:"causes"`
		Solutions   []string `json:"solutions"`
		Prevention  []string `json:"prevention"`
		References  []string `json:"references"`
	}

	genkit.DefineFlow(a.genkitInstance, "diagnoseError",
		func(ctx context.Context, errorMessage string) (ErrorDiagnosis, error) {
			response, err := a.AskWithStructuredOutput(ctx,
				"請診斷以下錯誤訊息並提供詳細的解決方案：\n\n"+errorMessage,
				ErrorDiagnosis{})
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
