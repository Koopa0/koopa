// Package agent implements the core AI agent system using Google's Genkit framework.
//
// Provides Agent type for orchestrating AI interactions with:
//   - Genkit AI model interactions with RAG-first design (retriever required, always enabled)
//   - Conversation history management (transient, in-memory - NOT persistent)
//   - Tool registration via internal/tools (file, system, network) and internal/mcp packages
//   - Security validation (path traversal, command injection, SSRF prevention)
//
// Agent is thread-safe for concurrent access (messages protected by RWMutex).
// Related packages: internal/tools, internal/mcp.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"runtime/debug"
	"sync"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/mcp"
	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/koopa0/koopa-cli/internal/tools"
	"google.golang.org/genai"
)

// Agent encapsulates Genkit AI functionality.
//
// Responsibilities: AI interactions, tool registration, conversation history (in-memory only).
// NOT responsible for: Database persistence (session/knowledge packages), session management, user interaction.
//
// Thread Safety: Thread-safe for concurrent access (messages protected by RWMutex).
// Security validators are immutable (safe to share). Tools safe to call concurrently.
type Agent struct {
	Genkit       *genkit.Genkit // Exported for external use (e.g., creating embedders)
	config       *config.Config
	modelRef     ai.ModelRef   // Type-safe model reference
	systemPrompt string        // System prompt text
	messages     []*ai.Message // Conversation history (transient, in-memory only)
	messagesMu   sync.RWMutex  // Protects messages field for concurrent access
	mcp          *mcp.Server   // MCP server connection (nil = not connected)
	mcpOnce      sync.Once     // Ensures MCP is initialized only once
	mcpErr       error         // Stores MCP initialization error
	retriever    ai.Retriever  // RAG retriever (required, always available)

	// Security validators (immutable after creation, safe for concurrent reads)
	pathValidator *security.Path
	cmdValidator  *security.Command
	httpValidator *security.HTTP
	envValidator  *security.Env
}

// New creates a new Agent instance with RAG support.
// Accepts pre-initialized Genkit instance and retriever (resolves circular dependency, enables DI and testing).
// Registers tools and loads system prompt from Dotprompt file.
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

	// Genkit's GoogleAI plugin requires GEMINI_API_KEY environment variable
	// This should be set by the user before running the application
	// (validated in config.Validate() and cmd/root.go)

	// Initialize security validators (no global init, created per-agent)
	// SECURITY: Only allow access to current working directory (principle of least privilege)
	// Follows security constraint from koopa.prompt:115 -
	// "NEVER: Access files outside the current working directory without explicit permission"
	pathValidator, err := security.NewPath([]string{"."})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize path validator: %w", err)
	}

	cmdValidator := security.NewCommand()
	httpValidator := security.NewHTTP()
	envValidator := security.NewEnv()

	// Register core tools (file, system, network)
	tools.RegisterTools(g, pathValidator, cmdValidator, httpValidator, envValidator)

	// Load system prompt (from Dotprompt file)
	systemPrompt := genkit.LookupPrompt(g, "koopa")
	if systemPrompt == nil {
		return nil, fmt.Errorf("system prompt not found")
	}

	// Render prompt without language parameter (pure English UI, AI auto-detects response language)
	promptInput := map[string]any{
		"language": "English",
	}
	actionOpts, err := systemPrompt.Render(ctx, promptInput)
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
	// Safely convert MaxTokens (prevent integer overflow and underflow)
	maxTokens := cfg.MaxTokens
	if maxTokens < 0 {
		slog.Warn("negative MaxTokens detected, using default value",
			"invalid_value", maxTokens,
			"default_value", 2048)
		maxTokens = 2048 // Use safe default
	} else if maxTokens > math.MaxInt32 {
		slog.Warn("MaxTokens exceeds int32 limit, clamping to maximum",
			"invalid_value", maxTokens,
			"clamped_value", math.MaxInt32)
		maxTokens = math.MaxInt32
	}
	modelRef := googlegenai.GoogleAIModelRef(cfg.ModelName, &genai.GenerateContentConfig{
		Temperature:     genai.Ptr(cfg.Temperature),
		MaxOutputTokens: int32(maxTokens), // #nosec G115 -- overflow/underflow checks above
	})

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

	return agent, nil
}

// Ask asks the AI a question and gets a response (always uses tools and RAG)
func (a *Agent) Ask(ctx context.Context, question string) (result string, err error) {
	// Panic recovery for stability
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic recovered in Ask: %v", r)
			slog.Error("panic in Ask",
				"error", r,
				"stack", string(debug.Stack()))
		}
	}()

	// Use core generation logic with prompt option
	response, err := a.generate(ctx, question, ai.WithPrompt(question))
	if err != nil {
		return "", err
	}

	return response.Text(), nil
}

// Chat multi-turn conversation (maintains history, always uses tools and RAG)
func (a *Agent) Chat(ctx context.Context, userInput string) (result string, err error) {
	// Panic recovery for stability
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic recovered in Chat: %v", r)
			slog.Error("panic in Chat",
				"error", r,
				"stack", string(debug.Stack()))
		}
	}()

	// Add user message to history (write lock)
	a.messagesMu.Lock()
	a.messages = append(a.messages, ai.NewUserMessage(ai.NewTextPart(userInput)))
	// Create a copy of messages for generate() to avoid holding lock during generation
	messagesCopy := make([]*ai.Message, len(a.messages))
	copy(messagesCopy, a.messages)
	a.messagesMu.Unlock()

	// Use core generation logic with message history (no lock needed)
	response, err := a.generate(ctx, userInput, ai.WithMessages(messagesCopy...))
	if err != nil {
		return "", err
	}

	// Add AI response to history (write lock)
	a.messagesMu.Lock()
	a.messages = append(a.messages, response.Message)
	a.trimHistoryIfNeeded()
	a.messagesMu.Unlock()

	return response.Text(), nil
}

// ChatStream multi-turn conversation with simulated streaming.
// Since Genkit doesn't support real streaming when tools are used, we implement
// simulated streaming by outputting the response word-by-word after generation.
func (a *Agent) ChatStream(ctx context.Context, userInput string, streamCallback func(chunk string)) (result string, err error) {
	// Panic recovery for stability
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic recovered in ChatStream: %v", r)
			slog.Error("panic in ChatStream",
				"error", r,
				"stack", string(debug.Stack()))
		}
	}()

	// Add user message to history (write lock)
	a.messagesMu.Lock()
	a.messages = append(a.messages, ai.NewUserMessage(ai.NewTextPart(userInput)))
	// Create a copy of messages for generate() to avoid holding lock during generation
	messagesCopy := make([]*ai.Message, len(a.messages))
	copy(messagesCopy, a.messages)
	a.messagesMu.Unlock()

	// Track if real streaming happened
	realStreamHappened := false

	// Try real streaming first (only works if no tools are called)
	streamOpt := ai.WithStreaming(func(ctx context.Context, chunk *ai.ModelResponseChunk) error {
		if streamCallback != nil && chunk.Text() != "" {
			streamCallback(chunk.Text())
			realStreamHappened = true
		}
		return nil
	})

	// Generate response (with or without streaming depending on tool usage, no lock needed)
	response, err := a.generate(ctx, userInput, ai.WithMessages(messagesCopy...), streamOpt)
	if err != nil {
		return "", err
	}

	finalText := response.Text()

	// If real streaming didn't happen (tool calls blocked it), simulate streaming
	if !realStreamHappened && streamCallback != nil && finalText != "" {
		slog.Debug("using simulated streaming", "text_length", len(finalText))
		simulateStreaming(finalText, streamCallback)
	} else if realStreamHappened {
		slog.Debug("real streaming occurred")
	}

	// Add AI response to history (write lock)
	a.messagesMu.Lock()
	a.messages = append(a.messages, response.Message)
	a.trimHistoryIfNeeded()
	a.messagesMu.Unlock()

	return finalText, nil
}

// ClearHistory clears the conversation history
func (a *Agent) ClearHistory() {
	a.messagesMu.Lock()
	defer a.messagesMu.Unlock()
	a.messages = []*ai.Message{}
}

// HistoryLength retrieves the conversation history length
func (a *Agent) HistoryLength() int {
	a.messagesMu.RLock()
	defer a.messagesMu.RUnlock()
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

// generate is the core generation logic shared by Ask, Chat, and ChatStream.
// Handles: RAG retrieval, tool collection, option preparation, and generation.
// Eliminates code duplication while maintaining distinct behaviors via extraOpts.
func (a *Agent) generate(ctx context.Context, userInput string, extraOpts ...ai.GenerateOption) (response *ai.ModelResponse, err error) {
	// Panic recovery for core generation logic
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic recovered in generate: %v", r)
			slog.Error("panic in generate",
				"error", r,
				"stack", string(debug.Stack()))
		}
	}()

	// Step 1: Retrieve relevant documents using RAG
	ragResp, err := a.retriever.Retrieve(ctx, &ai.RetrieverRequest{
		Query:   ai.DocumentFromText(userInput, nil),
		Options: map[string]any{"k": a.config.RAGTopK},
	})
	if err != nil {
		// Log warning but continue without RAG context
		slog.Warn("RAG retrieval failed, continuing without context",
			"error", err,
			"input_preview", truncateString(userInput, 50))
	}

	// Step 2: Get all registered tools (local + MCP)
	toolRefs := a.tools(ctx)

	// Step 3: Prepare generation options (base options + caller-specific options + RAG docs)
	opts := a.prepareGenerateOptions(toolRefs, ragResp, err, userInput, extraOpts...)

	// Step 4: Generate response
	response, err = genkit.Generate(ctx, a.Genkit, opts...)
	if err != nil {
		return nil, fmt.Errorf("generate failed: %w", err)
	}

	return response, nil
}

// tools retrieves all registered tools (including MCP tools)
// Design: Simple, concise naming for private methods
func (a *Agent) tools(ctx context.Context) []ai.ToolRef {
	// Get tool names from central registry (single source of truth)
	toolNames := tools.ToolNames()

	toolRefs := make([]ai.ToolRef, 0, len(toolNames))

	// Add locally registered tools
	for _, name := range toolNames {
		if tool := genkit.LookupTool(a.Genkit, name); tool != nil {
			toolRefs = append(toolRefs, tool)
		}
	}

	// If MCP is connected, add MCP tools
	if a.mcp != nil {
		mcpTools, err := a.mcp.Tools(ctx, a.Genkit)
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

// ConnectMCP connects to MCP servers (thread-safe, ensures single initialization)
func (a *Agent) ConnectMCP(ctx context.Context, serverConfigs []mcp.Config) error {
	a.mcpOnce.Do(func() {
		server, err := mcp.New(ctx, a.Genkit, serverConfigs)
		if err != nil {
			a.mcpErr = fmt.Errorf("unable to connect MCP: %w", err)
			return
		}
		a.mcp = server
		slog.Info("MCP connected successfully", "server_count", len(serverConfigs))
	})
	return a.mcpErr
}

// MCP retrieves the MCP server (if connected)
func (a *Agent) MCP() *mcp.Server {
	return a.mcp
}

// trimHistoryIfNeeded checks and limits conversation history length (sliding window mechanism)
// Strategy: keep most recent N messages
func (a *Agent) trimHistoryIfNeeded() {
	maxMessages := a.config.MaxHistoryMessages

	// 0 means unlimited
	if maxMessages <= 0 {
		// MEMORY WARNING: Monitor for potential memory leaks when unlimited
		if len(a.messages) > 1000 {
			// Estimate memory usage (rough estimate: ~1KB per message)
			estimatedMB := len(a.messages) / 1024
			slog.Warn("conversation history growing large with unlimited mode",
				"message_count", len(a.messages),
				"estimated_memory_mb", estimatedMB,
				"max_history_messages", maxMessages,
				"suggestion", "consider setting max_history_messages to limit memory usage")
		}
		return
	}

	// If history exceeds limit, keep only most recent maxMessages
	// Use max() to ensure non-negative start index
	a.messages = a.messages[max(0, len(a.messages)-maxMessages):]
}

// prepareGenerateOptions prepares common generation options for AI requests.
// Returns base options (model, system, tools) + extraOpts + RAG documents (if available).
func (a *Agent) prepareGenerateOptions(
	tools []ai.ToolRef,
	ragResp *ai.RetrieverResponse,
	err error,
	userInput string,
	extraOpts ...ai.GenerateOption,
) []ai.GenerateOption {
	// Start with base options (model, system, tools)
	opts := []ai.GenerateOption{
		ai.WithModel(a.modelRef),
		ai.WithSystem(a.systemPrompt),
		ai.WithTools(tools...),
	}

	// Append caller-specific options (e.g., WithPrompt, WithMessages, WithStreaming)
	opts = append(opts, extraOpts...)

	// Add retrieved documents if RAG retrieval succeeded and returned documents
	if err == nil && ragResp != nil && len(ragResp.Documents) > 0 {
		opts = append(opts, ai.WithDocs(ragResp.Documents...))
		slog.Debug("RAG: using retrieved documents",
			"count", len(ragResp.Documents),
			"input_preview", truncateString(userInput, 50))
	}

	return opts
}

// truncateString truncates a string to maxLen characters for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// simulateStreaming simulates character-by-character streaming output for better UX
// when real streaming is blocked (e.g., during tool execution)
func simulateStreaming(text string, callback func(chunk string)) {
	// Stream character by character with delay to create visible typing effect
	// Optimized for readability: slower than real streaming but feels more interactive

	runes := []rune(text)
	const charsPerChunk = 1 // Output 1 char at a time for clear typing effect
	const delayMs = 30      // 30ms between chars (visible typing speed, ~33 chars/sec)

	for i := 0; i < len(runes); i += charsPerChunk {
		end := i + charsPerChunk
		if end > len(runes) {
			end = len(runes)
		}

		chunk := string(runes[i:end])
		callback(chunk)

		// Slightly longer pause after punctuation for natural rhythm
		switch chunk {
		case "。", "，", "！", "？", ".", ",", "!", "?":
			time.Sleep(delayMs * 2 * time.Millisecond) // 60ms after punctuation
		case "\n":
			time.Sleep(delayMs * 3 * time.Millisecond) // 90ms after newline
		default:
			time.Sleep(delayMs * time.Millisecond)
		}
	}
}
