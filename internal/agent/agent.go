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

// Agent encapsulates Genkit AI functionality
type Agent struct {
	genkitInstance *genkit.Genkit
	config         *config.Config
	modelRef       ai.ModelRef   // Type-safe model reference
	systemMessage  *ai.Message   // System prompt (loaded from Dotprompt)
	messages       []*ai.Message // Conversation history
	useTools       bool          // Whether to use tools
	mcpManager     *MCPManager   // MCP manager (optional)
	useMCP         bool          // Whether to use MCP tools
	memory         interface{}   // Memory instance (optional, using interface{} to avoid circular dependency)
	currentSession int64         // Current session ID (0 means not in use)
}

// New creates a new Agent instance
func New(ctx context.Context, cfg *config.Config) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Genkit's GoogleAI plugin requires API key from environment variable
	// Ensure environment variable is set (supports KOOPA_GEMINI_API_KEY)
	if cfg.GeminiAPIKey != "" {
		_ = os.Setenv("GEMINI_API_KEY", cfg.GeminiAPIKey)
	}

	// Initialize Genkit (enable Dotprompt support)
	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}),
		genkit.WithPromptDir("./prompts"),
	)

	// Register tools
	registerTools(g)

	// Load system prompt (from Dotprompt file)
	systemPrompt := genkit.LookupPrompt(g, "koopa")
	if systemPrompt == nil {
		return nil, fmt.Errorf("system prompt not found")
	}

	// Render prompt to get messages (no input needed as koopa.prompt has no input parameters)
	actionOpts, err := systemPrompt.Render(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to render system prompt: %w", err)
	}

	// Extract system message
	var systemMessage *ai.Message
	if len(actionOpts.Messages) > 0 {
		systemMessage = actionOpts.Messages[0]
	} else {
		return nil, fmt.Errorf("system prompt contains no messages")
	}

	// Create type-safe model reference (pair model with config)
	// Use config file settings to override prompt file settings
	// Safely convert MaxTokens (prevent integer overflow)
	maxTokens := cfg.MaxTokens
	if maxTokens > math.MaxInt32 {
		maxTokens = math.MaxInt32
	}
	modelRef := googlegenai.GoogleAIModelRef(cfg.ModelName, &genai.GenerateContentConfig{
		Temperature:     genai.Ptr(cfg.Temperature),
		MaxOutputTokens: int32(maxTokens),
	})

	// Initialize conversation history with system message
	messages := []*ai.Message{systemMessage}

	agent := &Agent{
		genkitInstance: g,
		config:         cfg,
		modelRef:       modelRef,
		systemMessage:  systemMessage,
		messages:       messages,
		useTools:       false,
		mcpManager:     nil, // MCP disabled by default
		useMCP:         false,
		memory:         nil, // Memory disabled by default
		currentSession: 0,   // No current session
	}

	// Define all Genkit Flows (after Agent is fully initialized)
	DefineFlows(agent)

	return agent, nil
}

// Ask asks the AI a question and gets a response (without using tools)
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

// AskWithTools asks the AI a question and gets a response (using tools)
func (a *Agent) AskWithTools(ctx context.Context, question string) (string, error) {
	// Look up all registered tools
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

// Chat multi-turn conversation (maintains history)
func (a *Agent) Chat(ctx context.Context, userInput string) (string, error) {
	// Add user message to history
	a.messages = append(a.messages, ai.NewUserMessage(ai.NewTextPart(userInput)))

	// Prepare Generate options
	opts := []ai.GenerateOption{
		ai.WithModel(a.modelRef),
		ai.WithMessages(a.messages...),
	}

	// If tools are enabled, add tools
	if a.useTools {
		tools := a.getAllTools(ctx)
		opts = append(opts, ai.WithTools(tools...))
	}

	// Generate response
	response, err := genkit.Generate(ctx, a.genkitInstance, opts...)
	if err != nil {
		return "", fmt.Errorf("generate failed: %w", err)
	}

	// Add AI response to history
	a.messages = append(a.messages, response.Message)

	// Check and limit history length
	a.trimHistoryIfNeeded()

	return response.Text(), nil
}

// ChatStream multi-turn conversation (streaming mode)
func (a *Agent) ChatStream(ctx context.Context, userInput string, streamCallback func(chunk string)) (string, error) {
	// Add user message to history
	a.messages = append(a.messages, ai.NewUserMessage(ai.NewTextPart(userInput)))

	// Prepare Generate options
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

	// If tools are enabled, add tools
	if a.useTools {
		tools := a.getAllTools(ctx)
		opts = append(opts, ai.WithTools(tools...))
	}

	// Generate response
	response, err := genkit.Generate(ctx, a.genkitInstance, opts...)
	if err != nil {
		return "", fmt.Errorf("generate failed: %w", err)
	}

	// Add AI response to history
	a.messages = append(a.messages, response.Message)

	// Check and limit history length
	a.trimHistoryIfNeeded()

	return response.Text(), nil
}

// SetTools sets whether to use tools
func (a *Agent) SetTools(enabled bool) {
	a.useTools = enabled
}

// GetToolsEnabled retrieves the tool enabled status
func (a *Agent) GetToolsEnabled() bool {
	return a.useTools
}

// ClearHistory clears the conversation history
func (a *Agent) ClearHistory() {
	// Reset conversation history but keep system message
	a.messages = []*ai.Message{a.systemMessage}
}

// GetHistoryLength retrieves the conversation history length
func (a *Agent) GetHistoryLength() int {
	return len(a.messages)
}

// AskWithStructuredOutput asks the AI a question and gets structured output
// T must be a JSON-serializable struct type
// outputExample is used to infer the output type, usually pass a zero value of that type (e.g., MyStruct{})
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

// getAllTools retrieves all registered tools (including MCP tools)
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

	// Add locally registered tools
	for _, name := range toolNames {
		if tool := genkit.LookupTool(a.genkitInstance, name); tool != nil {
			tools = append(tools, tool)
		}
	}

	// If MCP is enabled, add MCP tools
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

// EnableMCP enables MCP and configures servers (optional)
func (a *Agent) EnableMCP(ctx context.Context, serverConfigs []MCPServerConfig) error {
	if a.mcpManager == nil {
		// Use mcp package types
		var mcpConfigs []mcp.MCPServerConfig
		for _, cfg := range serverConfigs {
			mcpConfigs = append(mcpConfigs, cfg.Config)
		}

		manager, err := NewMCPManager(ctx, a.genkitInstance, mcpConfigs)
		if err != nil {
			return fmt.Errorf("unable to enable MCP: %w", err)
		}
		a.mcpManager = manager
	}
	a.useMCP = true
	return nil
}

// DisableMCP disables MCP
func (a *Agent) DisableMCP() {
	a.useMCP = false
}

// GetMCPManager retrieves the MCP manager (if enabled)
func (a *Agent) GetMCPManager() *MCPManager {
	return a.mcpManager
}

// GetMCPEnabled retrieves the MCP enabled status
func (a *Agent) GetMCPEnabled() bool {
	return a.useMCP
}

// MCPServerConfig is a convenience type for MCP server configuration
type MCPServerConfig struct {
	Name   string
	Config mcp.MCPServerConfig
}

// trimHistoryIfNeeded checks and limits conversation history length (sliding window mechanism)
// Strategy: keep system message + most recent N messages
func (a *Agent) trimHistoryIfNeeded() {
	maxMessages := a.config.MaxHistoryMessages

	// 0 means unlimited
	if maxMessages <= 0 {
		return
	}

	// +1 because we need to count the system message
	if len(a.messages) <= maxMessages+1 {
		return
	}

	// Keep system message (first one) and most recent maxMessages messages
	// Calculate starting position to keep
	keepFromIndex := len(a.messages) - maxMessages

	// Rebuild messages: system message + most recent N messages
	newMessages := make([]*ai.Message, 0, maxMessages+1)
	newMessages = append(newMessages, a.systemMessage) // Keep system message
	newMessages = append(newMessages, a.messages[keepFromIndex:]...)

	a.messages = newMessages
}
