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
	"github.com/koopa0/koopa/internal/agent/flows"
	agenttools "github.com/koopa0/koopa/internal/agent/tools"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/security"
	"google.golang.org/genai"
)

// Agent encapsulates Genkit AI functionality
//
// # Architecture and Responsibilities
//
// Agent is responsible for:
//   - AI model interactions (via Genkit)
//   - Tool and Flow registration
//   - Conversation history management (transient, in-memory)
//   - Security validation coordination
//
// Agent is NOT responsible for:
//   - Database persistence (handled by internal/memory package)
//   - Session management (handled by cmd layer)
//   - User interaction (handled by cmd layer)
//
// This separation of concerns allows:
//   - Agent to be reusable across different persistence backends
//   - cmd layer to orchestrate Agent and Memory independently
//   - Clear testing boundaries
//
// # Lifecycle and Concurrency
//
// Agent instances are stateful and NOT safe for concurrent use:
//   - Each Agent maintains conversation history (messages field)
//
// Intended Usage Patterns:
//
//  1. CLI Application (Current Design):
//     Each command execution creates a new Agent instance.
//     cmd layer creates both Agent and Memory, coordinates them.
//     Example: cmd/chat.go creates agent + mem, calls both independently.
//
//  2. Long-lived Agent (Chat Mode):
//     Create one Agent per chat session.
//     Messages accumulate in the Agent throughout the session.
//     cmd layer persists messages via Memory package.
//
//  3. Web Service (Future):
//     Create a new Agent per request, OR
//     Use a per-session Agent with proper synchronization.
//     Persistence handled separately via Memory package.
//
// Thread Safety:
//   - Agent itself is NOT thread-safe
//   - Security validators (pathValidator, etc.) are immutable after creation
//   - Tools and Flows are registered once during Agent.New() and are safe to call concurrently
//
// Best Practice:
//   Treat Agent as a per-session or per-request object, not a singleton.
type Agent struct {
	genkitInstance *genkit.Genkit
	config         *config.Config
	modelRef       ai.ModelRef   // Type-safe model reference
	systemPrompt   string        // System prompt text
	messages       []*ai.Message // Conversation history (transient, in-memory only)
	mcpManager     *MCPManager   // MCP manager (nil = not connected)

	// Security validators (immutable after creation, safe for concurrent reads)
	pathValidator *security.PathValidator
	cmdValidator  *security.CommandValidator
	httpValidator *security.HTTPValidator
	envValidator  *security.EnvValidator
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

	// Initialize security validators (no global init, created per-agent)
	homeDir, err := security.GetHomeDir()
	if err != nil {
		// If GetHomeDir fails, use empty whitelist (only allow working directory)
		homeDir = ""
	}

	pathValidator, err := security.NewPathValidator([]string{homeDir})
	if err != nil {
		// If initialization fails, use empty whitelist (only allow working directory)
		pathValidator, _ = security.NewPathValidator([]string{})
	}

	cmdValidator := security.NewCommandValidator()
	httpValidator := security.NewHTTPValidator()
	envValidator := security.NewEnvValidator()

	// Initialize Genkit (enable Dotprompt support)
	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}),
		genkit.WithPromptDir("./prompts"),
	)

	// Register tools (pass validators via dependency injection)
	agenttools.RegisterTools(g, pathValidator, cmdValidator, httpValidator, envValidator)

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

	// Extract system prompt text
	var systemPromptText string
	if len(actionOpts.Messages) > 0 && len(actionOpts.Messages[0].Content) > 0 {
		systemPromptText = actionOpts.Messages[0].Content[0].Text
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
		MaxOutputTokens: int32(maxTokens), // #nosec G115 -- overflow check on lines 75-78
	})

	// Define all Genkit Flows (stateless design, pass pathValidator)
	flows.DefineFlows(g, modelRef, systemPromptText, pathValidator)

	// Initialize conversation history (empty, will be managed by Agent methods)
	messages := []*ai.Message{}

	agent := &Agent{
		genkitInstance: g,
		config:         cfg,
		modelRef:       modelRef,
		systemPrompt:   systemPromptText,
		messages:       messages,
		mcpManager:     nil, // MCP not connected by default
		// Store validators for use by Agent methods
		pathValidator: pathValidator,
		cmdValidator:  cmdValidator,
		httpValidator: httpValidator,
		envValidator:  envValidator,
	}

	return agent, nil
}

// Ask asks the AI a question and gets a response (always uses tools)
func (a *Agent) Ask(ctx context.Context, question string) (string, error) {
	// Get all registered tools (including MCP tools if enabled)
	tools := a.getAllTools(ctx)

	response, err := genkit.Generate(ctx, a.genkitInstance,
		ai.WithModel(a.modelRef),
		ai.WithSystem(a.systemPrompt),
		ai.WithPrompt(question),
		ai.WithTools(tools...),
	)
	if err != nil {
		return "", fmt.Errorf("generate failed: %w", err)
	}

	return response.Text(), nil
}

// Chat multi-turn conversation (maintains history, always uses tools)
func (a *Agent) Chat(ctx context.Context, userInput string) (string, error) {
	// Add user message to history
	a.messages = append(a.messages, ai.NewUserMessage(ai.NewTextPart(userInput)))

	// Get all registered tools (including MCP tools if enabled)
	tools := a.getAllTools(ctx)

	// Prepare Generate options
	opts := []ai.GenerateOption{
		ai.WithModel(a.modelRef),
		ai.WithSystem(a.systemPrompt),
		ai.WithMessages(a.messages...),
		ai.WithTools(tools...),
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

// ChatStream multi-turn conversation (streaming mode, always uses tools)
func (a *Agent) ChatStream(ctx context.Context, userInput string, streamCallback func(chunk string)) (string, error) {
	// Add user message to history
	a.messages = append(a.messages, ai.NewUserMessage(ai.NewTextPart(userInput)))

	// Get all registered tools (including MCP tools if enabled)
	tools := a.getAllTools(ctx)

	// Prepare Generate options
	opts := []ai.GenerateOption{
		ai.WithModel(a.modelRef),
		ai.WithSystem(a.systemPrompt),
		ai.WithMessages(a.messages...),
		ai.WithStreaming(func(ctx context.Context, chunk *ai.ModelResponseChunk) error {
			if streamCallback != nil {
				streamCallback(chunk.Text())
			}
			return nil
		}),
		ai.WithTools(tools...),
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

// ClearHistory clears the conversation history
func (a *Agent) ClearHistory() {
	// Reset conversation history
	a.messages = []*ai.Message{}
}

// GetHistoryLength retrieves the conversation history length
func (a *Agent) GetHistoryLength() int {
	return len(a.messages)
}

// AskWithStructuredOutput asks the AI a question and gets structured output
// T must be a JSON-serializable struct type
// outputExample is used to infer the output type, usually pass a zero value of that type (e.g., MyStruct{})
func (a *Agent) AskWithStructuredOutput(ctx context.Context, question string, outputExample any) (*ai.ModelResponse, error) {
	response, err := genkit.Generate(ctx, a.genkitInstance,
		ai.WithModel(a.modelRef),
		ai.WithSystem(a.systemPrompt),
		ai.WithPrompt(question),
		ai.WithOutputType(outputExample),
	)
	if err != nil {
		return nil, fmt.Errorf("generate failed: %w", err)
	}

	return response, nil
}

// getAllTools retrieves all registered tools (including MCP tools)
func (a *Agent) getAllTools(ctx context.Context) []ai.ToolRef {
	// Get tool names from central registry (single source of truth)
	toolNames := agenttools.GetToolNames()

	tools := make([]ai.ToolRef, 0, len(toolNames))

	// Add locally registered tools
	for _, name := range toolNames {
		if tool := genkit.LookupTool(a.genkitInstance, name); tool != nil {
			tools = append(tools, tool)
		}
	}

	// If MCP is connected, add MCP tools
	if a.mcpManager != nil {
		mcpTools, err := a.mcpManager.GetActiveTools(ctx, a.genkitInstance)
		if err == nil {
			for _, mcpTool := range mcpTools {
				tools = append(tools, mcpTool)
			}
		}
	}

	return tools
}

// ConnectMCP connects to MCP servers
func (a *Agent) ConnectMCP(ctx context.Context, serverConfigs []MCPServerConfig) error {
	if a.mcpManager == nil {
		// Use mcp package types
		var mcpConfigs []mcp.MCPServerConfig
		for _, cfg := range serverConfigs {
			mcpConfigs = append(mcpConfigs, cfg.Config)
		}

		manager, err := NewMCPManager(ctx, a.genkitInstance, mcpConfigs)
		if err != nil {
			return fmt.Errorf("unable to connect MCP: %w", err)
		}
		a.mcpManager = manager
	}
	return nil
}

// GetMCPManager retrieves the MCP manager (if connected)
func (a *Agent) GetMCPManager() *MCPManager {
	return a.mcpManager
}

// MCPServerConfig is a convenience type for MCP server configuration
type MCPServerConfig struct {
	Name   string
	Config mcp.MCPServerConfig
}

// trimHistoryIfNeeded checks and limits conversation history length (sliding window mechanism)
// Strategy: keep most recent N messages
func (a *Agent) trimHistoryIfNeeded() {
	maxMessages := a.config.MaxHistoryMessages

	// 0 means unlimited
	if maxMessages <= 0 {
		return
	}

	// If history exceeds limit, keep only most recent maxMessages
	if len(a.messages) > maxMessages {
		// Keep most recent maxMessages messages
		a.messages = a.messages[len(a.messages)-maxMessages:]
	}
}
