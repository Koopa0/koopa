// Package agent implements the core AI agent system using Google's Genkit framework.
//
// Provides Agent type for orchestrating AI interactions with:
//   - Genkit AI model interactions with RAG-first design (retriever required, always enabled)
//   - Conversation history management (in-memory with optional database persistence)
//   - Tool registration via internal/tools (file, system, network) and internal/mcp packages
//   - Security validation (path traversal, command injection, SSRF prevention)
//
// Agent is thread-safe for concurrent access (messages protected by RWMutex).
// Related packages: internal/tools, internal/mcp, internal/session.
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
	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/mcp"
	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/tools"
	"google.golang.org/genai"
)

// Generator defines an interface for generating model responses,
// allowing for mocking in tests.
type Generator interface {
	Generate(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error)
}

// SessionStore defines the interface for session persistence operations.
// Following Go best practices: interfaces are defined by the consumer (agent), not the provider (session package).
// This allows Agent to depend on abstraction rather than concrete implementation, improving testability.
type SessionStore interface {
	// CreateSession creates a new conversation session
	CreateSession(ctx context.Context, title, modelName, systemPrompt string) (*session.Session, error)

	// GetSession retrieves a session by ID
	GetSession(ctx context.Context, sessionID uuid.UUID) (*session.Session, error)

	// GetMessages retrieves messages for a session with pagination
	GetMessages(ctx context.Context, sessionID uuid.UUID, limit, offset int) ([]*session.Message, error)

	// AddMessages adds multiple messages to a session in batch
	AddMessages(ctx context.Context, sessionID uuid.UUID, messages []*session.Message) error
}

// genkitGenerator is the production implementation of the Generator interface.
type genkitGenerator struct {
	g *genkit.Genkit
}

// Generate calls the underlying genkit.Generate function.
func (gg *genkitGenerator) Generate(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error) {
	return genkit.Generate(ctx, gg.g, opts...)
}

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
	mcp          *mcp.Server   // MCP server connection (nil = not connected)
	mcpOnce      sync.Once     // Ensures MCP is initialized only once
	mcpErr       error         // Stores MCP initialization error
	retriever    ai.Retriever  // RAG retriever (required, always available)

	// Session persistence (P1 - optional)
	sessionStore     SessionStore // Session data access layer (nil = persistence disabled)
	currentSessionID *uuid.UUID   // Current session ID (nil = no active session)
	logger           *slog.Logger // Structured logger
}

// New creates a new Agent instance with RAG support and session persistence.
// Accepts pre-initialized Genkit instance and retriever (resolves circular dependency, enables DI and testing).
// Registers tools and loads system prompt from Dotprompt file.
//
// Parameters:
//   - sessionStore: Session persistence layer (required, use NewNoopSessionStore() for stub)
//   - logger: Structured logger (required, use slog.Default() if unsure)
func New(
	ctx context.Context,
	cfg *config.Config,
	g *genkit.Genkit,
	retriever ai.Retriever,
	sessionStore SessionStore,
	logger *slog.Logger,
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

	if sessionStore == nil {
		return nil, fmt.Errorf("sessionStore is required (use NewNoopSessionStore() for stub)")
	}

	if logger == nil {
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

	// Register core tools (file, system, network)
	// Note: Tools internally hold references to validators; Agent doesn't need to retain them
	tools.RegisterTools(g, pathValidator, cmdValidator, httpValidator, envValidator)

	// Register confirmation tool (interrupt mechanism, agent-specific)
	RegisterConfirmationTool(g)

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

	agent := &Agent{
		g:            g,
		generator:    &genkitGenerator{g: g},
		config:       cfg,
		modelRef:     modelRef,
		systemPrompt: systemPromptText,
		messages:     messages,
		mcp:          nil,       // MCP not connected by default
		retriever:    retriever, // RAG retriever (always available)
		sessionStore: sessionStore,
		logger:       logger,
	}

	// Load current session (attempt to restore from local state)
	if err := agent.loadCurrentSession(ctx); err != nil {
		logger.Warn("failed to load current session, starting with empty history",
			"error", err)
		// Loading failure is not fatal - Agent continues with empty history
	}

	return agent, nil
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
	response, err = a.generator.Generate(ctx, opts...)
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
		if tool := genkit.LookupTool(a.g, name); tool != nil {
			toolRefs = append(toolRefs, tool)
		}
	}

	// If MCP is connected, add MCP tools
	if a.mcp != nil {
		mcpTools, err := a.mcp.Tools(ctx, a.g)
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
		server, err := mcp.New(ctx, a.g, serverConfigs)
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

// Execute runs the agent with interrupt mechanism support.
// Returns an event channel for UI layer to consume agent events (text, interrupts, errors).
// This is the new primary interaction method that supports human-in-the-loop confirmations.
func (a *Agent) Execute(ctx context.Context, input string) <-chan Event {
	eventCh := make(chan Event, 10)

	go func() {
		defer close(eventCh)

		// Step 1: Prepare message history (Agent is the sole owner of history)
		a.messagesMu.Lock()
		userMessage := ai.NewUserMessage(ai.NewTextPart(input))
		a.messages = append(a.messages, userMessage)
		messagesCopy := make([]*ai.Message, len(a.messages))
		copy(messagesCopy, a.messages)
		a.messagesMu.Unlock()

		// Track new messages for batch persistence (P1)
		var newMessages []*session.Message
		if a.currentSessionID != nil {
			newMessages = append(newMessages, &session.Message{
				Role:    "user",
				Content: userMessage.Content,
			})
		}

		// Step 2: Automatic RAG (only on first request)
		ragResp, err := a.retriever.Retrieve(ctx, &ai.RetrieverRequest{
			Query:   ai.DocumentFromText(input, nil),
			Options: map[string]any{"k": a.config.RAGTopK},
		})
		if err != nil {
			slog.Warn("RAG retrieval failed in Execute, continuing without context",
				"error", err,
				"input_preview", truncateString(input, 50))
		}

		// Step 3: Prepare streaming callback
		streamingOpt := ai.WithStreaming(func(ctx context.Context, chunk *ai.ModelResponseChunk) error {
			if chunk.Text() != "" {
				eventCh <- Event{Type: EventTypeText, TextChunk: chunk.Text()}
			}
			return nil
		})

		// Main loop: Handle potential multi-turn interactions
		for {
			// Step 4: Prepare current turn request options
			toolRefs := a.tools(ctx)
			opts := []ai.GenerateOption{
				ai.WithModel(a.modelRef),
				ai.WithSystem(a.systemPrompt),
				ai.WithMessages(messagesCopy...),
				ai.WithTools(toolRefs...),
				streamingOpt,
			}
			if ragResp != nil && len(ragResp.Documents) > 0 {
				opts = append(opts, ai.WithDocs(ragResp.Documents...))
				ragResp = nil // RAG only in first round
			}

			// Step 5: Call Genkit generate
			response, err := a.generator.Generate(ctx, opts...)
			if err != nil {
				eventCh <- Event{Type: EventTypeError, Error: err}
				return
			}

			// Step 6: Add model's thought/action to current turn history
			messagesCopy = append(messagesCopy, response.Message)

			// Step 6.5: Log tool calls for debugging and monitoring
			for _, part := range response.Message.Content {
				if part.ToolRequest != nil {
					a.logger.Debug("tool called",
						"tool_name", part.ToolRequest.Name,
						"finish_reason", response.FinishReason)
				}
				if part.ToolResponse != nil {
					a.logger.Debug("tool response received",
						"tool_name", part.ToolResponse.Name)
				}
			}

			// Step 7: Check finish reason
			switch response.FinishReason {
			case ai.FinishReasonInterrupted:
				// Defensive check: Ensure interrupts array is not empty
				interrupts := response.Interrupts()
				if len(interrupts) == 0 {
					a.logger.Warn("FinishReasonInterrupted but no interrupts found",
						"response_text", truncateString(response.Text(), 100))
					// Treat as normal completion to avoid crash
					eventCh <- Event{Type: EventTypeComplete, IsComplete: true}
					return
				}

				var toolResponses []*ai.Part
				for _, interrupt := range interrupts {
					// 7.1. Construct and send interrupt event
					resumeCh := make(chan ConfirmationResponse)
					eventCh <- Event{
						Type: EventTypeInterrupt,
						Interrupt: &InterruptEvent{
							ToolName:      extractToolName(interrupt),
							Parameters:    extractParams(interrupt),
							Reason:        extractReason(interrupt),
							rawInterrupt:  interrupt,
							ResumeChannel: resumeCh,
						},
					}

					// 7.2. Block and wait for UI layer's decision (with context cancellation support)
					var decision ConfirmationResponse
					select {
					case decision = <-resumeCh:
						// Normal path: received user decision
					case <-ctx.Done():
						// Context cancelled: abort gracefully
						a.logger.Debug("context cancelled while waiting for user confirmation")
						eventCh <- Event{
							Type:  EventTypeError,
							Error: fmt.Errorf("operation cancelled by user"),
						}
						return
					}

					// 7.3. Construct tool response
					toolResponses = append(toolResponses, buildToolResponse(interrupt, decision))
				}

				// 7.4. Add tool responses to history, prepare for next round
				messagesCopy = append(messagesCopy, ai.NewMessage(ai.RoleTool, nil, toolResponses...))
				continue // Loop back, call Generate with updated history

			case ai.FinishReasonStop, ai.FinishReasonUnknown:
				// Step 8: Normal completion, update Agent's main history
				// Note: FinishReasonUnknown can occur with streaming, treat as normal completion
				a.messagesMu.Lock()
				a.messages = messagesCopy
				a.trimHistoryIfNeeded()
				a.messagesMu.Unlock()

				// Batch save all new messages to database (P1)
				if a.currentSessionID != nil {
					newMessages = append(newMessages, &session.Message{
						Role:    "model",
						Content: response.Message.Content,
					})

					if err := a.sessionStore.AddMessages(ctx, *a.currentSessionID, newMessages); err != nil {
						a.logger.Warn("failed to save messages to database",
							"session_id", *a.currentSessionID,
							"message_count", len(newMessages),
							"error", err)
						// Continue execution - persistence failure is not fatal
					}
				}

				eventCh <- Event{Type: EventTypeComplete, IsComplete: true}
				return

			case ai.FinishReasonLength:
				// Max tokens reached
				eventCh <- Event{
					Type:  EventTypeError,
					Error: fmt.Errorf("response truncated: maximum token limit reached"),
				}
				return

			case ai.FinishReasonBlocked:
				// Content blocked by safety filter
				eventCh <- Event{
					Type:  EventTypeError,
					Error: fmt.Errorf("response blocked by safety filter"),
				}
				return

			default:
				// Other unexpected reasons
				eventCh <- Event{
					Type:  EventTypeError,
					Error: fmt.Errorf("unexpected finish reason: %s", response.FinishReason),
				}
				return
			}
		}
	}()

	return eventCh
}

// ============================================================================
// Session Management Methods (P1)
// ============================================================================

// loadCurrentSession loads the session specified in local state file.
// Called automatically by New().
// Loading failure is not fatal - Agent continues with empty history.
func (a *Agent) loadCurrentSession(ctx context.Context) error {
	// Read local state file
	sessionID, err := session.LoadCurrentSessionID()
	if err != nil {
		return fmt.Errorf("failed to load current session ID: %w", err)
	}

	if sessionID == nil {
		// No current session - this is normal
		return nil
	}

	// Load session messages from database
	messages, err := a.sessionStore.GetMessages(ctx, *sessionID, a.config.MaxHistoryMessages, 0)
	if err != nil {
		return fmt.Errorf("failed to load session messages: %w", err)
	}

	// Convert session.Message to ai.Message
	var aiMessages []*ai.Message
	for _, msg := range messages {
		aiMsg := &ai.Message{
			Role:    ai.Role(msg.Role),
			Content: msg.Content,
		}
		aiMessages = append(aiMessages, aiMsg)
	}

	// Update Agent state
	a.messagesMu.Lock()
	a.messages = aiMessages
	a.currentSessionID = sessionID
	a.messagesMu.Unlock()

	a.logger.Info("loaded session",
		"session_id", *sessionID,
		"message_count", len(aiMessages))

	return nil
}

// NewSession creates a new conversation session and switches to it.
// Clears current conversation history and starts fresh.
//
// Parameters:
//   - title: Session title (can be empty)
//
// Returns:
//   - *session.Session: Created session
//   - error: If creation fails
func (a *Agent) NewSession(ctx context.Context, title string) (*session.Session, error) {
	// Create new session in database
	newSession, err := a.sessionStore.CreateSession(ctx, title, a.config.ModelName, a.systemPrompt)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Save to local state file
	if err := session.SaveCurrentSessionID(newSession.ID); err != nil {
		return nil, fmt.Errorf("failed to save current session: %w", err)
	}

	// Clear current history
	a.messagesMu.Lock()
	a.messages = []*ai.Message{}
	a.currentSessionID = &newSession.ID
	a.messagesMu.Unlock()

	a.logger.Info("created new session",
		"session_id", newSession.ID,
		"title", newSession.Title)

	return newSession, nil
}

// SwitchSession switches to an existing session.
// Loads the session's conversation history from database.
//
// Parameters:
//   - sessionID: UUID of the session to switch to
//
// Returns:
//   - error: If switching fails
func (a *Agent) SwitchSession(ctx context.Context, sessionID uuid.UUID) error {
	// Save to local state file
	if err := session.SaveCurrentSessionID(sessionID); err != nil {
		return fmt.Errorf("failed to save current session: %w", err)
	}

	// Load session (same logic as loadCurrentSession)
	return a.loadCurrentSession(ctx)
}

// GetCurrentSession retrieves the current session information.
//
// Returns:
//   - *session.Session: Current session
//   - error: If no active session or retrieval fails
func (a *Agent) GetCurrentSession(ctx context.Context) (*session.Session, error) {
	if a.currentSessionID == nil {
		return nil, fmt.Errorf("no active session")
	}

	return a.sessionStore.GetSession(ctx, *a.currentSessionID)
}

// ============================================================================
// No-op Session Store - For testing and Phase 2-3 transition
// ============================================================================

// noopSessionStore is a no-op implementation of SessionStore.
// It provides no-op implementations for all methods, returning nil or empty values.
// This is used when session persistence is not required (e.g., in tests or before Phase 3).
//
// This follows the Go standard library pattern (similar to io.NopCloser).
// All operations are no-ops (do nothing) without causing errors.
type noopSessionStore struct{}

func (n *noopSessionStore) CreateSession(ctx context.Context, title, modelName, systemPrompt string) (*session.Session, error) {
	return nil, fmt.Errorf("session persistence not yet enabled (noopSessionStore)")
}

func (n *noopSessionStore) GetSession(ctx context.Context, sessionID uuid.UUID) (*session.Session, error) {
	return nil, fmt.Errorf("session persistence not yet enabled (noopSessionStore)")
}

func (n *noopSessionStore) GetMessages(ctx context.Context, sessionID uuid.UUID, limit, offset int) ([]*session.Message, error) {
	return nil, nil // Return empty messages, not an error
}

func (n *noopSessionStore) AddMessages(ctx context.Context, sessionID uuid.UUID, messages []*session.Message) error {
	// Silently succeed - no-op
	return nil
}

// NewNoopSessionStore creates a new noopSessionStore.
// Use this when session persistence is not required (e.g., in tests).
//
// This follows the Go standard library naming pattern (e.g., io.NopCloser).
func NewNoopSessionStore() SessionStore {
	return &noopSessionStore{}
}
