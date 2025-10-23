package agent

import (
	"context"
	"fmt"
	"math"
	"os"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/firebase/genkit/go/plugins/mcp"
	"github.com/koopa0/koopa/internal/config"
	"google.golang.org/genai"
)

// Agent 封裝 Genkit AI 功能
type Agent struct {
	genkitInstance *genkit.Genkit
	config         *config.Config
	modelRef       ai.ModelRef   // 型別安全的 model reference
	systemMessage  *ai.Message   // System prompt（從 Dotprompt 載入）
	messages       []*ai.Message // 對話歷史
	useTools       bool          // 是否使用工具
	mcpManager     *MCPManager   // MCP 管理器（可選）
	useMCP         bool          // 是否使用 MCP 工具
	memory         interface{}   // Memory 實例（可選，避免循環依賴用 interface{}）
	currentSession int64         // 當前會話 ID（0 表示未使用）
}

// New 創建新的 Agent 實例
func New(ctx context.Context, cfg *config.Config) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Genkit 的 GoogleAI 插件需要從環境變數讀取 API key
	// 確保環境變數已設置（支援 KOOPA_GEMINI_API_KEY）
	if cfg.GeminiAPIKey != "" {
		_ = os.Setenv("GEMINI_API_KEY", cfg.GeminiAPIKey)
	}

	// 初始化 Genkit（啟用 Dotprompt 支援）
	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}),
		genkit.WithPromptDir("./prompts"),
	)

	// 註冊工具
	registerTools(g)

	// 載入 system prompt（從 Dotprompt 檔案）
	systemPrompt := genkit.LookupPrompt(g, "koopa")
	if systemPrompt == nil {
		return nil, fmt.Errorf("找不到 system prompt")
	}

	// 渲染 prompt 以獲取 messages（不需要 input，因為 koopa.prompt 沒有輸入參數）
	actionOpts, err := systemPrompt.Render(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("渲染 system prompt 失敗: %w", err)
	}

	// 提取 system message
	var systemMessage *ai.Message
	if len(actionOpts.Messages) > 0 {
		systemMessage = actionOpts.Messages[0]
	} else {
		return nil, fmt.Errorf("system prompt 沒有包含任何 message")
	}

	// 創建型別安全的 model reference（配對 model 和 config）
	// 使用配置檔案中的設定覆蓋 prompt 檔案中的設定
	// 安全轉換 MaxTokens (防止整數溢出)
	maxTokens := cfg.MaxTokens
	if maxTokens > math.MaxInt32 {
		maxTokens = math.MaxInt32
	}
	modelRef := googlegenai.GoogleAIModelRef(cfg.ModelName, &genai.GenerateContentConfig{
		Temperature:     genai.Ptr(cfg.Temperature),
		MaxOutputTokens: int32(maxTokens),
	})

	// 初始化對話歷史，包含 system message
	messages := []*ai.Message{systemMessage}

	agent := &Agent{
		genkitInstance: g,
		config:         cfg,
		modelRef:       modelRef,
		systemMessage:  systemMessage,
		messages:       messages,
		useTools:       false,
		mcpManager:     nil, // MCP 默認未啟用
		useMCP:         false,
		memory:         nil, // Memory 默認未啟用
		currentSession: 0,   // 無當前會話
	}

	// 定義所有 Genkit Flows（在 Agent 完全初始化之後）
	DefineFlows(agent)

	return agent, nil
}

// Ask 向 AI 提問並獲取回應（不使用工具）
func (a *Agent) Ask(ctx context.Context, question string) (string, error) {
	messages := []*ai.Message{
		a.systemMessage,
		ai.NewUserMessage(ai.NewTextPart(question)),
	}

	response, err := genkit.Generate(ctx, a.genkitInstance,
		ai.WithModel(a.modelRef),
		ai.WithMessages(messages...),
	)
	if err != nil {
		return "", fmt.Errorf("generate failed: %w", err)
	}

	return response.Text(), nil
}

// AskWithTools 向 AI 提問並獲取回應（使用工具）
func (a *Agent) AskWithTools(ctx context.Context, question string) (string, error) {
	// 查找所有已註冊的工具
	tools := a.getAllTools(ctx)

	messages := []*ai.Message{
		a.systemMessage,
		ai.NewUserMessage(ai.NewTextPart(question)),
	}

	response, err := genkit.Generate(ctx, a.genkitInstance,
		ai.WithModel(a.modelRef),
		ai.WithMessages(messages...),
		ai.WithTools(tools...),
	)
	if err != nil {
		return "", fmt.Errorf("generate failed: %w", err)
	}

	return response.Text(), nil
}

// Chat 多輪對話（保持歷史記錄）
func (a *Agent) Chat(ctx context.Context, userInput string) (string, error) {
	// 添加用戶訊息到歷史
	a.messages = append(a.messages, ai.NewUserMessage(ai.NewTextPart(userInput)))

	// 準備 Generate 選項
	opts := []ai.GenerateOption{
		ai.WithModel(a.modelRef),
		ai.WithMessages(a.messages...),
	}

	// 如果啟用工具，添加工具
	if a.useTools {
		tools := a.getAllTools(ctx)
		opts = append(opts, ai.WithTools(tools...))
	}

	// 生成回應
	response, err := genkit.Generate(ctx, a.genkitInstance, opts...)
	if err != nil {
		return "", fmt.Errorf("generate failed: %w", err)
	}

	// 將 AI 回應添加到歷史
	a.messages = append(a.messages, response.Message)

	// 檢查並限制歷史長度
	a.trimHistoryIfNeeded()

	return response.Text(), nil
}

// ChatStream 多輪對話（streaming 模式）
func (a *Agent) ChatStream(ctx context.Context, userInput string, streamCallback func(chunk string)) (string, error) {
	// 添加用戶訊息到歷史
	a.messages = append(a.messages, ai.NewUserMessage(ai.NewTextPart(userInput)))

	// 準備 Generate 選項
	opts := []ai.GenerateOption{
		ai.WithModel(a.modelRef),
		ai.WithMessages(a.messages...),
		ai.WithStreaming(func(ctx context.Context, chunk *ai.ModelResponseChunk) error {
			if streamCallback != nil {
				streamCallback(chunk.Text())
			}
			return nil
		}),
	}

	// 如果啟用工具，添加工具
	if a.useTools {
		tools := a.getAllTools(ctx)
		opts = append(opts, ai.WithTools(tools...))
	}

	// 生成回應
	response, err := genkit.Generate(ctx, a.genkitInstance, opts...)
	if err != nil {
		return "", fmt.Errorf("generate failed: %w", err)
	}

	// 將 AI 回應添加到歷史
	a.messages = append(a.messages, response.Message)

	// 檢查並限制歷史長度
	a.trimHistoryIfNeeded()

	return response.Text(), nil
}

// SetTools 設定是否使用工具
func (a *Agent) SetTools(enabled bool) {
	a.useTools = enabled
}

// GetToolsEnabled 獲取工具啟用狀態
func (a *Agent) GetToolsEnabled() bool {
	return a.useTools
}

// ClearHistory 清除對話歷史
func (a *Agent) ClearHistory() {
	// 重置對話歷史，但保留 system message
	a.messages = []*ai.Message{a.systemMessage}
}

// GetHistoryLength 獲取對話歷史長度
func (a *Agent) GetHistoryLength() int {
	return len(a.messages)
}

// AskWithStructuredOutput 向 AI 提問並獲取結構化輸出
// T 必須是一個可以被 JSON 序列化的結構體類型
// outputExample 用於推斷輸出類型，通常傳入該類型的零值（如 MyStruct{}）
func (a *Agent) AskWithStructuredOutput(ctx context.Context, question string, outputExample any) (*ai.ModelResponse, error) {
	messages := []*ai.Message{
		a.systemMessage,
		ai.NewUserMessage(ai.NewTextPart(question)),
	}

	response, err := genkit.Generate(ctx, a.genkitInstance,
		ai.WithModel(a.modelRef),
		ai.WithMessages(messages...),
		ai.WithOutputType(outputExample),
	)
	if err != nil {
		return nil, fmt.Errorf("generate failed: %w", err)
	}

	return response, nil
}

// getAllTools 獲取所有已註冊的工具（包含 MCP 工具）
func (a *Agent) getAllTools(ctx context.Context) []ai.ToolRef {
	toolNames := []string{
		"currentTime",
		"readFile",
		"writeFile",
		"listFiles",
		"deleteFile",
		"executeCommand",
		"httpGet",
		"getEnv",
		"getFileInfo",
	}

	tools := make([]ai.ToolRef, 0, len(toolNames))

	// 添加本地註冊的工具
	for _, name := range toolNames {
		if tool := genkit.LookupTool(a.genkitInstance, name); tool != nil {
			tools = append(tools, tool)
		}
	}

	// 如果啟用了 MCP，添加 MCP 工具
	if a.useMCP && a.mcpManager != nil {
		mcpTools, err := a.mcpManager.GetActiveTools(ctx, a.genkitInstance)
		if err == nil {
			for _, mcpTool := range mcpTools {
				tools = append(tools, mcpTool)
			}
		}
	}

	return tools
}

// EnableMCP 啟用 MCP 並配置伺服器（可選）
func (a *Agent) EnableMCP(ctx context.Context, serverConfigs []MCPServerConfig) error {
	if a.mcpManager == nil {
		// 使用 mcp 包的類型
		var mcpConfigs []mcp.MCPServerConfig
		for _, cfg := range serverConfigs {
			mcpConfigs = append(mcpConfigs, cfg.Config)
		}

		manager, err := NewMCPManager(ctx, a.genkitInstance, mcpConfigs)
		if err != nil {
			return fmt.Errorf("無法啟用 MCP: %w", err)
		}
		a.mcpManager = manager
	}
	a.useMCP = true
	return nil
}

// DisableMCP 禁用 MCP
func (a *Agent) DisableMCP() {
	a.useMCP = false
}

// GetMCPManager 獲取 MCP 管理器（如果已啟用）
func (a *Agent) GetMCPManager() *MCPManager {
	return a.mcpManager
}

// GetMCPEnabled 獲取 MCP 啟用狀態
func (a *Agent) GetMCPEnabled() bool {
	return a.useMCP
}

// MCPServerConfig 是 MCP 伺服器配置的便利類型
type MCPServerConfig struct {
	Name   string
	Config mcp.MCPServerConfig
}

// trimHistoryIfNeeded 檢查並限制對話歷史長度（滑動窗口機制）
// 策略：保留 system message + 最近的 N 則訊息
func (a *Agent) trimHistoryIfNeeded() {
	maxMessages := a.config.MaxHistoryMessages

	// 0 表示無限制
	if maxMessages <= 0 {
		return
	}

	// +1 是因為要算上 system message
	if len(a.messages) <= maxMessages+1 {
		return
	}

	// 保留 system message（第一則）和最近的 maxMessages 則訊息
	// 計算要保留的起始位置
	keepFromIndex := len(a.messages) - maxMessages

	// 重建 messages：system message + 最近的 N 則
	newMessages := make([]*ai.Message, 0, maxMessages+1)
	newMessages = append(newMessages, a.systemMessage) // 保留 system message
	newMessages = append(newMessages, a.messages[keepFromIndex:]...)

	a.messages = newMessages
}
