package agent

import (
	"context"
	"os"

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
			// 讀取檔案內容
			content, err := genkit.Run(ctx, "read-file",
				func() (string, error) {
					data, err := os.ReadFile(input.FilePath)
					if err != nil {
						return "", err
					}
					return string(data), nil
				})
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
			// 讀取程式碼
			code, err := genkit.Run(ctx, "read-code",
				func() (string, error) {
					data, err := os.ReadFile(filePath)
					if err != nil {
						return "", err
					}
					return string(data), nil
				})
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
			// 讀取日誌
			logs, err := genkit.Run(ctx, "read-logs",
				func() (string, error) {
					data, err := os.ReadFile(logPath)
					if err != nil {
						return "", err
					}
					// 限制日誌大小
					if len(data) > 10000 {
						return string(data[len(data)-10000:]), nil
					}
					return string(data), nil
				})
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
			content, err := genkit.Run(ctx, "read-document",
				func() (string, error) {
					data, err := os.ReadFile(filePath)
					if err != nil {
						return "", err
					}
					// 限制長度
					if len(data) > 5000 {
						return string(data[:5000]) + "...", nil
					}
					return string(data), nil
				})
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
