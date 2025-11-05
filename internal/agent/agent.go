package agent

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/koopa0/koopa/internal/agent/flows"
	"github.com/koopa0/koopa/internal/agent/mcp"
	"github.com/koopa0/koopa/internal/agent/tools"
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
//
//	Treat Agent as a per-session or per-request object, not a singleton.
type Agent struct {
	Genkit       *genkit.Genkit // Exported for external use (e.g., creating embedders)
	config       *config.Config
	modelRef     ai.ModelRef   // Type-safe model reference
	systemPrompt string        // System prompt text
	messages     []*ai.Message // Conversation history (transient, in-memory only)
	mcp          *mcp.Server   // MCP server connection (nil = not connected)
	retriever    ai.Retriever  // RAG retriever (required, always available)

	// Security validators (immutable after creation, safe for concurrent reads)
	pathValidator *security.PathValidator
	cmdValidator  *security.CommandValidator
	httpValidator *security.HTTPValidator
	envValidator  *security.EnvValidator
}

// New creates a new Agent instance with RAG support.
//
// Parameters:
//   - ctx: Context for initialization
//   - cfg: Configuration (must be validated)
//   - g: Genkit instance (must be initialized with required plugins)
//   - retriever: RAG retriever (required, must not be nil)
//
// This function no longer initializes Genkit internally. Instead, it accepts
// a pre-initialized Genkit instance and retriever. This design:
//   - Resolves circular dependency (embedder needs Genkit, retriever needs embedder)
//   - Follows dependency injection principle
//   - Makes testing easier (can inject mocks)
//   - Ensures RAG is always available as a core capability
func New(ctx context.Context, cfg *config.Config, g *genkit.Genkit, retriever ai.Retriever) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if g == nil {
		return nil, fmt.Errorf("genkit instance is required")
	}

	if retriever == nil {
		return nil, fmt.Errorf("retriever is required for RAG functionality")
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

	// Register tools using the provided Genkit instance
	tools.RegisterTools(g, pathValidator, cmdValidator, httpValidator, envValidator)

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
		Genkit:       g,
		config:       cfg,
		modelRef:     modelRef,
		systemPrompt: systemPromptText,
		messages:     messages,
		mcp:          nil,       // MCP not connected by default
		retriever:    retriever, // RAG retriever (always available)
		// Store validators for use by Agent methods
		pathValidator: pathValidator,
		cmdValidator:  cmdValidator,
		httpValidator: httpValidator,
		envValidator:  envValidator,
	}

	slog.Info("agent initialized with RAG support",
		"model", cfg.ModelName,
		"rag_top_k", cfg.RAGTopK,
		"embedder", cfg.EmbedderModel)

	return agent, nil
}

// Ask asks the AI a question and gets a response (always uses tools and RAG)
func (a *Agent) Ask(ctx context.Context, question string) (string, error) {
	// Step 1: Retrieve relevant documents using RAG
	ragResp, err := a.retriever.Retrieve(ctx, &ai.RetrieverRequest{
		Query: ai.DocumentFromText(question, nil),
		Options: map[string]interface{}{"k": a.config.RAGTopK},
	})
	if err != nil {
		// Log warning but continue without RAG context
		slog.Warn("RAG retrieval failed, continuing without context",
			"error", err,
			"question_preview", truncateString(question, 50))
	}

	// Step 2: Get all registered tools
	tools := a.getAllTools(ctx)

	// Step 3: Prepare generation options
	opts := []ai.GenerateOption{
		ai.WithModel(a.modelRef),
		ai.WithSystem(a.systemPrompt),
		ai.WithPrompt(question),
		ai.WithTools(tools...),
	}

	// Step 4: Add retrieved documents if available
	if err == nil && len(ragResp.Documents) > 0 {
		opts = append(opts, ai.WithDocs(ragResp.Documents...))
		slog.Info("RAG: using retrieved documents",
			"count", len(ragResp.Documents),
			"question_preview", truncateString(question, 50))
	} else if err == nil {
		slog.Info("RAG: no documents found for question",
			"question_preview", truncateString(question, 50))
	}

	// Step 5: Generate response
	response, err := genkit.Generate(ctx, a.Genkit, opts...)
	if err != nil {
		return "", fmt.Errorf("generate failed: %w", err)
	}

	return response.Text(), nil
}

// Chat multi-turn conversation (maintains history, always uses tools and RAG)
func (a *Agent) Chat(ctx context.Context, userInput string) (string, error) {
	// Add user message to history
	a.messages = append(a.messages, ai.NewUserMessage(ai.NewTextPart(userInput)))

	// Step 1: Retrieve relevant documents using RAG
	ragResp, err := a.retriever.Retrieve(ctx, &ai.RetrieverRequest{
		Query: ai.DocumentFromText(userInput, nil),
		Options: map[string]interface{}{"k": a.config.RAGTopK},
	})
	if err != nil {
		slog.Warn("RAG retrieval failed, continuing without context",
			"error", err,
			"input_preview", truncateString(userInput, 50))
	}

	// Step 2: Get all registered tools
	tools := a.getAllTools(ctx)

	// Step 3: Prepare Generate options
	opts := []ai.GenerateOption{
		ai.WithModel(a.modelRef),
		ai.WithSystem(a.systemPrompt),
		ai.WithMessages(a.messages...),
		ai.WithTools(tools...),
	}

	// Step 4: Add retrieved documents if available
	if err == nil && len(ragResp.Documents) > 0 {
		opts = append(opts, ai.WithDocs(ragResp.Documents...))
		slog.Info("RAG: using retrieved documents",
			"count", len(ragResp.Documents),
			"input_preview", truncateString(userInput, 50))
	}

	// Step 5: Generate response
	response, err := genkit.Generate(ctx, a.Genkit, opts...)
	if err != nil {
		return "", fmt.Errorf("generate failed: %w", err)
	}

	// Add AI response to history
	a.messages = append(a.messages, response.Message)

	// Check and limit history length
	a.trimHistoryIfNeeded()

	return response.Text(), nil
}

// ChatStream multi-turn conversation (streaming mode, always uses tools and RAG)
func (a *Agent) ChatStream(ctx context.Context, userInput string, streamCallback func(chunk string)) (string, error) {
	// Add user message to history
	a.messages = append(a.messages, ai.NewUserMessage(ai.NewTextPart(userInput)))

	// Step 1: Retrieve relevant documents using RAG
	ragResp, err := a.retriever.Retrieve(ctx, &ai.RetrieverRequest{
		Query: ai.DocumentFromText(userInput, nil),
		Options: map[string]interface{}{"k": a.config.RAGTopK},
	})
	if err != nil {
		slog.Warn("RAG retrieval failed, continuing without context",
			"error", err,
			"input_preview", truncateString(userInput, 50))
	}

	// Step 2: Get all registered tools
	tools := a.getAllTools(ctx)

	// Step 3: Prepare Generate options
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

	// Step 4: Add retrieved documents if available
	if err == nil && len(ragResp.Documents) > 0 {
		opts = append(opts, ai.WithDocs(ragResp.Documents...))
		slog.Info("RAG: using retrieved documents (streaming)",
			"count", len(ragResp.Documents),
			"input_preview", truncateString(userInput, 50))
	}

	// Step 5: Generate response
	response, err := genkit.Generate(ctx, a.Genkit, opts...)
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
	response, err := genkit.Generate(ctx, a.Genkit,
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
	toolNames := tools.GetToolNames()

	toolRefs := make([]ai.ToolRef, 0, len(toolNames))

	// Add locally registered tools
	for _, name := range toolNames {
		if tool := genkit.LookupTool(a.Genkit, name); tool != nil {
			toolRefs = append(toolRefs, tool)
		}
	}

	// If MCP is connected, add MCP tools
	if a.mcp != nil {
		mcpTools, err := a.mcp.GetTools(ctx, a.Genkit)
		if err != nil {
			slog.Warn("failed to get MCP tools, using local tools only", "error", err)
		} else {
			for _, mcpTool := range mcpTools {
				toolRefs = append(toolRefs, mcpTool)
			}
		}
	}

	return toolRefs
}

// ConnectMCP connects to MCP servers
func (a *Agent) ConnectMCP(ctx context.Context, serverConfigs []mcp.Config) error {
	if a.mcp == nil {
		server, err := mcp.New(ctx, a.Genkit, serverConfigs)
		if err != nil {
			return fmt.Errorf("unable to connect MCP: %w", err)
		}
		a.mcp = server
		slog.Info("MCP connected successfully", "server_count", len(serverConfigs))
	}
	return nil
}

// GetMCP retrieves the MCP server (if connected)
func (a *Agent) GetMCP() *mcp.Server {
	return a.mcp
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

// truncateString truncates a string to maxLen characters for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
