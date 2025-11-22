// Package agent implements the core AI agent system using Google's Genkit framework.
//
// Provides Agent type for orchestrating AI interactions with:
//   - Genkit AI model interactions with RAG-first design (retriever required, always enabled)
//   - Conversation history management (in-memory with optional database persistence)
//   - Tool registration via internal/tools (file, system, network)
//   - Security validation (path traversal, command injection, SSRF prevention)
//
// Agent is thread-safe for concurrent access (messages protected by RWMutex).
// Related packages: internal/tools, internal/session.
//
// NOTE: MCP Client support temporarily removed during Phase 2 refactoring.
// Phase 2 implements MCP Server (not client). MCP Client may be re-added in future if needed.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/config"
	// "github.com/koopa0/koopa-cli/internal/mcp" // Removed: Old MCP client, Phase 2 implements MCP server
	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/tools"
	"google.golang.org/genai"
)

// Agent encapsulates Genkit AI functionality.
//
// Responsibilities: AI interactions, tool registration, conversation history (in-memory and optional persistence).
// NOT responsible for: User interaction (cmd package handles CLI).
//
// Thread Safety: Thread-safe for concurrent access (messages protected by RWMutex).
// Tools (registered via tools.RegisterTools) are thread-safe and hold their own validators.
type Agent struct {
	g            *genkit.Genkit // Raw genkit instance for non-generative tasks (tool lookup, MCP, prompt loading)
	generator    Generator      // Interface for generating responses (enables mocking in tests)
	config       *config.Config
	modelRef     ai.ModelRef   // Type-safe model reference
	systemPrompt string        // System prompt text
	messages     []*ai.Message // Conversation history (in-memory, optionally persisted to database)
	messagesMu   sync.RWMutex  // Protects messages field for concurrent access
	kit          *tools.Kit    // Tool kit (Phase 1: Kit replaces Handler and Registry)
	// mcp          *mcp.Server     // Removed: Old MCP client (Phase 2 implements MCP server)
	// mcpOnce      sync.Once       // Removed: Old MCP client
	// mcpErr       error           // Removed: Old MCP client
	retriever ai.Retriever // RAG retriever (required, always available)

	// Session persistence (P1 - optional)
	sessionStore     SessionStore   // Session data access layer (nil = persistence disabled)
	currentSessionID *uuid.UUID     // Current session ID (nil = no active session)
	knowledgeStore   KnowledgeStore // Knowledge store for semantic search (P2 - required, interface for testability)
	logger           *slog.Logger   // Structured logger
}

// New creates a new Agent instance with RAG support and session persistence.
// Accepts pre-initialized Genkit instance and retriever (resolves circular dependency, enables DI and testing).
// Registers tools and loads system prompt from Dotprompt file.
//
// Parameters:
//   - ctx: Context
//   - cfg: Configuration
//   - g: Genkit instance
//   - retriever: RAG retriever
//   - opts: Functional options for configuration
func New(
	ctx context.Context,
	cfg *config.Config,
	g *genkit.Genkit,
	retriever ai.Retriever,
	opts ...Option,
) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if g == nil {
		return nil, fmt.Errorf("genkit instance is required")
	}

	if retriever == nil {
		return nil, fmt.Errorf("retriever is required for RAG functionality")
	}

	// Default values
	agent := &Agent{
		g:         g,
		generator: &genkitGenerator{g: g},
		config:    cfg,
		// mcp:       nil,       // Removed: Old MCP client
		retriever: retriever, // RAG retriever (always available)
		logger:    slog.Default(),
	}

	// Apply options
	for _, opt := range opts {
		opt(agent)
	}

	// Validate required dependencies after options
	if agent.sessionStore == nil {
		return nil, fmt.Errorf("sessionStore is required (provide via WithSessionStore option)")
	}

	if agent.knowledgeStore == nil {
		return nil, fmt.Errorf("knowledgeStore is required")
	}

	if agent.logger == nil {
		return nil, fmt.Errorf("logger is required (use slog.Default())")
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

	// Create Kit with all required dependencies (Phase 1: Kit replaces Handler and Registry)
	kitCfg := tools.KitConfig{
		PathVal:        pathValidator,
		CmdVal:         cmdValidator,
		EnvVal:         envValidator,
		HTTPVal:        httpValidator,
		KnowledgeStore: agent.knowledgeStore,
	}

	kit, err := tools.NewKit(kitCfg, tools.WithLogger(agent.logger))
	if err != nil {
		return nil, fmt.Errorf("failed to create kit: %w", err)
	}

	// Register Kit tools to Genkit
	if err := kit.Register(g); err != nil {
		return nil, fmt.Errorf("failed to register kit tools: %w", err)
	}

	agent.kit = kit

	// Load system prompt (from Dotprompt file)
	systemPrompt := genkit.LookupPrompt(g, "koopa")
	if systemPrompt == nil {
		return nil, fmt.Errorf("system prompt not found")
	}

	// Render prompt with language parameter from config
	// "auto" means AI will auto-detect and match user's language
	language := cfg.Language
	if language == "" || language == "auto" {
		language = "the same language as the user's input (auto-detect)"
	}
	promptInput := map[string]any{
		"language": language,
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

	// Initialize type-safe model reference
	agent.modelRef = modelRef
	agent.systemPrompt = systemPromptText
	agent.messages = messages

	// Load current session (attempt to restore from local state)
	if err := agent.loadCurrentSession(ctx); err != nil {
		agent.logger.Warn("failed to load current session, starting with empty history",
			"error", err)
		// Loading failure is not fatal - Agent continues with empty history
	}

	return agent, nil
}

// tools returns locally registered tools only.
// Separated from MCP tools for clear responsibility boundary (Phase 1: Kit provides tools).
//
// Design: Single responsibility - only handles local tools.
func (a *Agent) tools(ctx context.Context) []ai.ToolRef {
	return a.kit.All(ctx, a.g)
}

// Removed: Old MCP Client methods
// Phase 2 implements MCP Server (not client). These methods may be re-added in future if needed.
//
// Previously:
// - mcpTools(): returned MCP tools if connected
// - allTools(): aggregated local + MCP tools
// - ConnectMCP(): connected to MCP servers
// - MCP(): retrieved MCP server instance

// allTools returns all available tools (currently only local tools).
// Previously aggregated local + MCP tools, now simplified during Phase 2.
//
// TODO: If MCP Client is re-added in future, restore aggregation logic.
func (a *Agent) allTools(ctx context.Context) []ai.ToolRef {
	return a.tools(ctx)
}

// truncateString truncates a string to maxLen characters for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ============================================================================
// Execute Method and Helpers
// ============================================================================

// Execute runs the agent with the given input and returns the complete response.
// This is a synchronous, blocking operation that uses Genkit's native ReAct engine.
// Following 建議.md architecture: single Generate call with WithMaxTurns.
//
// Architecture decisions (v4 consensus):
//   - Trust Genkit framework to handle multi-turn tool calling
//   - Sacrifice interrupt/human-in-the-loop for simplicity and elegance
//   - Sacrifice real-time streaming feedback
//   - Use Genkit's built-in OpenTelemetry for observability (no custom metrics)
func (a *Agent) Execute(ctx context.Context, input string) (*Response, error) {
	// Step 1: Prepare context with timeout
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Step 2: Prepare messages and RAG
	messagesCopy := a.prepareMessages(input)
	ragDocs := a.performRAG(ctx, input)

	// Step 3: Build options and generate (Phase 3: Use allTools for local + MCP)
	toolRefs := a.allTools(ctx)
	opts := a.buildGenerateOptions(messagesCopy, ragDocs, toolRefs)

	response, err := a.generator.Generate(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("agent execution failed: %w", err)
	}

	// Step 4: Update history and persist
	responseHistory := a.updateHistory(response)
	a.persistMessages(ctx, response, responseHistory)

	// Step 5: Async vectorization
	go a.asyncVectorize()

	// Step 6: Return response
	return &Response{
		FinalText: response.Text(),
		History:   responseHistory,
	}, nil
}

// prepareMessages creates a copy of message history with the new user message appended.
// Thread-safe operation using RWMutex.
func (a *Agent) prepareMessages(input string) []*ai.Message {
	a.messagesMu.Lock()
	defer a.messagesMu.Unlock()

	userMessage := ai.NewUserMessage(ai.NewTextPart(input))
	messagesCopy := make([]*ai.Message, len(a.messages))
	copy(messagesCopy, a.messages)
	return append(messagesCopy, userMessage)
}

// performRAG performs RAG retrieval for the given input.
// Returns documents if successful, nil otherwise (non-fatal).
func (a *Agent) performRAG(ctx context.Context, input string) []*ai.Document {
	ragResp, err := a.retriever.Retrieve(ctx, &ai.RetrieverRequest{
		Query:   ai.DocumentFromText(input, nil),
		Options: map[string]any{"k": a.config.RAGTopK},
	})

	if err != nil {
		a.logger.Warn("RAG retrieval failed, continuing without context",
			"error", err,
			"input_preview", truncateString(input, 50))
		return nil
	}

	if ragResp == nil || len(ragResp.Documents) == 0 {
		return nil
	}

	return ragResp.Documents
}

// buildGenerateOptions constructs Genkit generation options.
func (a *Agent) buildGenerateOptions(messages []*ai.Message, ragDocs []*ai.Document, toolRefs []ai.ToolRef) []ai.GenerateOption {
	opts := []ai.GenerateOption{
		ai.WithModel(a.modelRef),
		ai.WithSystem(a.systemPrompt),
		ai.WithMessages(messages...),
		ai.WithTools(toolRefs...),
		ai.WithMaxTurns(a.config.MaxTurns),
	}

	if len(ragDocs) > 0 {
		opts = append(opts, ai.WithDocs(ragDocs...))
	}

	return opts
}

// updateHistory updates agent's message history with response messages.
// Uses defer/recover to handle mock scenarios where History() might panic.
// Filters to keep only user and model messages, trims if needed.
// Returns the history for reuse (avoiding duplicate History() calls).
func (a *Agent) updateHistory(response *ai.ModelResponse) []*ai.Message {
	// Safe history retrieval with panic recovery
	var responseHistory []*ai.Message
	func() {
		defer func() {
			if r := recover(); r != nil {
				a.logger.Debug("response.History() panicked (likely mock), using fallback", "panic", r)
				responseHistory = nil
			}
		}()
		responseHistory = response.History()
	}()

	a.messagesMu.Lock()
	defer a.messagesMu.Unlock()

	if responseHistory != nil {
		// Filter to keep only user and model messages
		a.messages = nil
		for _, msg := range responseHistory {
			if msg.Role == ai.RoleUser || msg.Role == ai.RoleModel {
				a.messages = append(a.messages, msg)
			}
		}
	} else {
		// Fallback: manually construct history (for mock scenarios)
		if response.Message != nil {
			a.messages = append(a.messages, response.Message)
		}
	}

	a.trimHistoryIfNeeded()

	return responseHistory
}

// persistMessages persists messages to session store if a session is active.
// Non-fatal operation - logs warnings but doesn't fail execution.
func (a *Agent) persistMessages(ctx context.Context, response *ai.ModelResponse, responseHistory []*ai.Message) {
	if a.currentSessionID == nil {
		return
	}

	var newMessages []*session.Message

	// Build message list from history or fallback
	if responseHistory != nil {
		for _, msg := range responseHistory {
			if msg.Role == ai.RoleUser || msg.Role == ai.RoleModel {
				newMessages = append(newMessages, &session.Message{
					Role:    string(msg.Role),
					Content: msg.Content,
				})
			}
		}
	} else {
		// Fallback for mock scenarios
		if response.Message != nil {
			newMessages = append(newMessages, &session.Message{
				Role:    string(ai.RoleModel),
				Content: response.Message.Content,
			})
		}
	}

	if err := a.sessionStore.AddMessages(ctx, *a.currentSessionID, newMessages); err != nil {
		a.logger.Warn("failed to save messages to database",
			"session_id", *a.currentSessionID,
			"message_count", len(newMessages),
			"error", err)
	}
}

// asyncVectorize launches asynchronous vectorization of the conversation turn.
func (a *Agent) asyncVectorize() {
	vectorCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := a.vectorizeConversationTurn(vectorCtx); err != nil {
		a.logger.Warn("conversation vectorization failed (non-critical)", "error", err)
	}
}
