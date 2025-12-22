package chat

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/postgresql"
	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/koopa0/koopa/internal/log"
	"github.com/koopa0/koopa/internal/rag"
	"github.com/koopa0/koopa/internal/session"
)

// Agent name and description constants
const (
	// Name is the unique identifier for the Chat agent.
	Name = "chat"

	// Description describes the Chat agent's capabilities.
	Description = "A general purpose chat agent that can help with various tasks using tools and knowledge base."

	// KoopaPromptName is the name of the Dotprompt file for the Chat agent.
	// This corresponds to prompts/koopa.prompt.
	// NOTE: The LLM model is configured in the Dotprompt file, not via Config.
	KoopaPromptName = "koopa"

	// FallbackResponseMessage is the message returned when the model produces an empty response.
	FallbackResponseMessage = "I apologize, but I couldn't generate a response. Please try rephrasing your question."
)

// Response represents the complete result of an agent execution.
type Response struct {
	FinalText    string            // Model's final text output
	ToolRequests []*ai.ToolRequest // Tool requests made during execution
}

// StreamCallback is called for each chunk of streaming response.
// The chunk contains partial content that can be immediately displayed to the user.
// Return an error to abort the stream.
type StreamCallback func(ctx context.Context, chunk *ai.ModelResponseChunk) error

// Config contains all required parameters for Chat agent.
type Config struct {
	Genkit       *genkit.Genkit
	Retriever    ai.Retriever // Genkit Retriever for RAG context
	SessionStore *session.Store
	Logger       log.Logger
	Tools        []ai.Tool // Pre-registered tools from RegisterXxxTools()

	// Configuration values
	// NOTE: LLM model is configured in prompts/koopa.prompt, not here
	MaxTurns int    // Maximum agentic loop turns
	RAGTopK  int    // Number of RAG documents to retrieve
	Language string // Response language preference

	// Resilience configuration
	RetryConfig          RetryConfig          // LLM retry settings (zero-value uses defaults)
	CircuitBreakerConfig CircuitBreakerConfig // Circuit breaker settings (zero-value uses defaults)
	RateLimiter          *rate.Limiter        // Optional: proactive rate limiting (nil = use default)

	// Token management
	TokenBudget TokenBudget // Token budget for context window (zero-value uses defaults)
}

// validate checks if all required parameters are present.
func (cfg Config) validate() error {
	if cfg.Genkit == nil {
		return errors.New("genkit instance is required")
	}
	if cfg.Retriever == nil {
		return errors.New("retriever is required")
	}
	if cfg.SessionStore == nil {
		return errors.New("session store is required")
	}
	if cfg.Logger == nil {
		return errors.New("logger is required")
	}
	if len(cfg.Tools) == 0 {
		return errors.New("at least one tool is required")
	}
	return nil
}

// Chat is Koopa's main conversational agent.
// It provides LLM-powered conversations with tool calling and knowledge base integration.
//
// Chat is stateless and uses dependency injection.
// Required parameters are provided via Config struct.
//
// All configuration values are captured immutably at construction time
// to ensure thread-safe concurrent access.
type Chat struct {
	// Immutable configuration (captured at construction)
	languagePrompt string // Resolved language for prompt template
	maxTurns       int
	ragTopK        int

	// Resilience (captured at construction)
	retryConfig    RetryConfig
	circuitBreaker *CircuitBreaker
	rateLimiter    *rate.Limiter // Proactive rate limiting (nil = disabled)

	// Token management (captured at construction)
	tokenBudget TokenBudget

	// Dependencies (read-only after construction)
	g         *genkit.Genkit
	retriever ai.Retriever // Genkit Retriever for RAG context
	sessions  *session.Store
	logger    log.Logger
	tools     []ai.Tool    // Pre-registered tools (passed in via Config)
	toolRefs  []ai.ToolRef // Cached at construction (ai.Tool implements ai.ToolRef)
	toolNames string       // Cached as comma-separated for logging
	prompt    ai.Prompt    // Cached Dotprompt instance (model configured in prompt file)
}

// New creates a new Chat agent with required configuration.
//
// NOTE: The LLM model is configured in prompts/koopa.prompt, not via Config.
//
// Example:
//
//	chat, err := chat.New(chat.Config{
//	    Genkit:       g,
//	    Retriever:    retriever,  // Genkit Retriever from postgresql.DefineRetriever
//	    SessionStore: sessionStore,
//	    Logger:       logger,
//	    Tools:        tools,  // Pre-registered via RegisterXxxTools()
//	    MaxTurns:     cfg.MaxTurns,
//	    RAGTopK:      cfg.RAGTopK,
//	    Language:     cfg.Language,
//	})
func New(cfg Config) (*Chat, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// Apply defaults for optional configuration values
	maxTurns := cfg.MaxTurns
	if maxTurns <= 0 {
		maxTurns = 5 // Default fallback
	}

	// Resolve language once at construction
	languagePrompt := cfg.Language
	if languagePrompt == "" || languagePrompt == "auto" {
		languagePrompt = "the same language as the user's input (auto-detect)"
	}

	// Apply resilience defaults if not configured
	retryConfig := cfg.RetryConfig
	if retryConfig.MaxRetries == 0 {
		retryConfig = DefaultRetryConfig()
	}

	cbConfig := cfg.CircuitBreakerConfig
	if cbConfig.FailureThreshold == 0 {
		cbConfig = DefaultCircuitBreakerConfig()
	}

	tokenBudget := cfg.TokenBudget
	if tokenBudget.MaxHistoryTokens == 0 {
		tokenBudget = DefaultTokenBudget()
	}

	// Use provided rate limiter or create default
	// Default: 10 requests/sec sustained, burst of 30
	rl := cfg.RateLimiter
	if rl == nil {
		rl = rate.NewLimiter(10, 30)
	}

	// Cache tool refs and names at construction (zero allocation per request)
	toolRefs := make([]ai.ToolRef, len(cfg.Tools))
	names := make([]string, len(cfg.Tools))
	for i, t := range cfg.Tools {
		toolRefs[i] = t
		names[i] = t.Name()
	}

	c := &Chat{
		// Immutable configuration
		languagePrompt: languagePrompt,
		maxTurns:       maxTurns,
		ragTopK:        cfg.RAGTopK,

		// Resilience
		retryConfig:    retryConfig,
		circuitBreaker: NewCircuitBreaker(cbConfig),
		rateLimiter:    rl,

		// Token management
		tokenBudget: tokenBudget,

		// Dependencies
		g:         cfg.Genkit,
		retriever: cfg.Retriever,
		sessions:  cfg.SessionStore,
		logger:    cfg.Logger,
		tools:     cfg.Tools,                 // Already registered with Genkit
		toolRefs:  toolRefs,                  // Cached for ai.WithTools()
		toolNames: strings.Join(names, ", "), // Cached for logging
	}

	// Load Dotprompt (koopa.prompt) - REQUIRED
	// NOTE: Model is configured in the prompt file, not via Config
	c.prompt = genkit.LookupPrompt(c.g, KoopaPromptName)
	if c.prompt == nil {
		return nil, fmt.Errorf("dotprompt '%s' not found: ensure prompts directory is configured correctly", KoopaPromptName)
	}
	c.logger.Debug("loaded dotprompt successfully", "prompt_name", KoopaPromptName)

	c.logger.Info("chat agent initialized",
		"totalTools", len(c.tools),
		"maxTurns", c.maxTurns,
	)

	return c, nil
}

// Execute runs the chat agent with the given input (non-streaming).
// This is a convenience wrapper around ExecuteStream with nil callback.
func (c *Chat) Execute(ctx context.Context, sessionID uuid.UUID, input string) (*Response, error) {
	return c.ExecuteStream(ctx, sessionID, input, nil)
}

// ExecuteStream runs the chat agent with optional streaming output.
// If callback is non-nil, it is called for each chunk of the response as it's generated.
// If callback is nil, the response is generated without streaming (equivalent to Execute).
// The final response is always returned after generation completes.
func (c *Chat) ExecuteStream(ctx context.Context, sessionID uuid.UUID, input string, callback StreamCallback) (*Response, error) {
	streaming := callback != nil
	c.logger.Debug("executing chat agent",
		"session_id", sessionID,
		"streaming", streaming)

	// Load session history
	history, err := c.sessions.GetHistory(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get history: %w", err)
	}

	// Generate response using unified core logic
	resp, err := c.generateResponse(ctx, input, history.Messages(), callback)
	if err != nil {
		return nil, err
	}

	responseText := resp.Text()

	// Only apply fallback when truly empty (no text AND no tool requests)
	// When LLM returns empty text but has tool requests, this is valid agentic behavior
	if strings.TrimSpace(responseText) == "" && len(resp.ToolRequests()) == 0 {
		c.logger.Warn("model returned empty response with no tool requests",
			"session_id", sessionID)
		responseText = FallbackResponseMessage
	}

	// Update history with user input and response
	history.Add(input, responseText)

	// Save updated history to session store using AppendMessages (preferred)
	newMessages := []*ai.Message{
		ai.NewUserMessage(ai.NewTextPart(input)),
		ai.NewModelMessage(ai.NewTextPart(responseText)),
	}
	if err := c.sessions.AppendMessages(ctx, sessionID, newMessages); err != nil {
		c.logger.Error("failed to append messages to history", "error", err)
		// Don't fail the request, just log the error
	}

	// Return formatted response
	return &Response{
		FinalText:    responseText,
		ToolRequests: resp.ToolRequests(),
	}, nil
}

// generateResponse is the unified response generation logic for both streaming and non-streaming modes.
// If callback is non-nil, streaming is enabled; otherwise, standard generation is used.
func (c *Chat) generateResponse(ctx context.Context, input string, historyMessages []*ai.Message, callback StreamCallback) (*ai.ModelResponse, error) {
	// Build messages: deep copy history and append current user input
	// CRITICAL: Deep copy is required to prevent DATA RACE in Genkit's renderMessages()
	// Genkit modifies msg.Content in-place, so concurrent executions sharing the same
	// message objects will race. We must copy each message, not just the slice.
	messages := deepCopyMessages(historyMessages)

	// Apply token budget before adding new message
	// This ensures we don't exceed context window limits
	messages = c.truncateHistory(messages, c.tokenBudget.MaxHistoryTokens)

	messages = append(messages, ai.NewUserMessage(ai.NewTextPart(input)))

	// Retrieve relevant documents for RAG context (graceful fallback on error)
	ragDocs := c.retrieveRAGContext(ctx, input)

	// Build execute options (using cached toolRefs and languagePrompt)
	opts := []ai.PromptExecuteOption{
		ai.WithInput(map[string]any{
			"language": c.languagePrompt,
		}),
		ai.WithMessagesFn(func(_ context.Context, _ any) ([]*ai.Message, error) {
			return messages, nil
		}),
		ai.WithTools(c.toolRefs...),
		ai.WithMaxTurns(c.maxTurns),
	}

	// Add RAG documents if available
	if len(ragDocs) > 0 {
		opts = append(opts, ai.WithDocs(ragDocs...))
	}

	// Add streaming callback if provided
	if callback != nil {
		opts = append(opts, ai.WithStreaming(callback))
	}

	// Diagnostic logging (using cached toolNames - zero allocation)
	c.logger.Debug("executing prompt",
		"toolCount", len(c.tools),
		"tools", c.toolNames,
		"maxTurns", c.maxTurns,
		"queryLength", len(input),
	)

	// Check circuit breaker before attempting request
	if err := c.circuitBreaker.Allow(); err != nil {
		c.logger.Warn("circuit breaker is open, rejecting request",
			"state", c.circuitBreaker.State().String())
		return nil, fmt.Errorf("service unavailable: %w", err)
	}

	// Execute prompt with retry mechanism
	resp, err := c.executeWithRetry(ctx, opts)
	if err != nil {
		c.circuitBreaker.Failure()
		return nil, err
	}

	c.circuitBreaker.Success()
	return resp, nil
}

// ragRetrievalTimeout is the maximum time allowed for RAG document retrieval.
// This prevents slow queries from blocking the entire chat request.
const ragRetrievalTimeout = 5 * time.Second

// retrieveRAGContext retrieves relevant documents from the knowledge base.
// Returns empty slice on error (graceful degradation).
func (c *Chat) retrieveRAGContext(ctx context.Context, query string) []*ai.Document {
	// Skip RAG if topK is not configured or zero
	if c.ragTopK <= 0 {
		return nil
	}

	// Add dedicated timeout for RAG retrieval to prevent slow queries
	// from blocking the entire chat request
	ragCtx, cancel := context.WithTimeout(ctx, ragRetrievalTimeout)
	defer cancel()

	// Build retriever request with source_type filter for files (documents)
	req := &ai.RetrieverRequest{
		Query: ai.DocumentFromText(query, nil),
		Options: &postgresql.RetrieverOptions{
			Filter: "source_type = '" + rag.SourceTypeFile + "'",
			K:      c.ragTopK,
		},
	}

	// Retrieve documents with timeout
	resp, err := c.retriever.Retrieve(ragCtx, req)
	if err != nil {
		// Use Debug for expected errors (timeout, cancellation)
		// Use Warn for unexpected errors (DB issues, etc.) that ops should know about
		if ctx.Err() != nil || ragCtx.Err() != nil {
			c.logger.Debug("RAG retrieval canceled or timed out (continuing without context)",
				"error", err,
				"timeout", ragRetrievalTimeout,
				"query_length", len(query))
		} else {
			c.logger.Warn("RAG retrieval failed (continuing without context)",
				"error", err,
				"query_length", len(query))
		}
		return nil
	}

	if len(resp.Documents) > 0 {
		c.logger.Debug("retrieved RAG context",
			"document_count", len(resp.Documents),
			"query_length", len(query))
	}

	return resp.Documents
}

// deepCopyMessages creates independent copies of Message and Part structs.
//
// WORKAROUND: Genkit's renderMessages() modifies msg.Content in-place,
// causing data races in concurrent executions. This function creates
// independent struct copies to prevent the race.
//
// Tracking: https://github.com/firebase/genkit/issues/XXX (TODO: file issue)
// Tested version: github.com/firebase/genkit/go v1.20.0
//
// To remove this workaround:
// 1. Upgrade Genkit: go get -u github.com/firebase/genkit/go@latest
// 2. Run: go test -race ./internal/agent/chat/...
// 3. If race detector passes, remove deepCopyMessages() calls
// 4. If race still fails, update version in this comment
func deepCopyMessages(msgs []*ai.Message) []*ai.Message {
	if msgs == nil {
		return nil // Preserve nil vs empty slice semantics
	}
	copied := make([]*ai.Message, len(msgs))
	for i, msg := range msgs {
		parts := make([]*ai.Part, len(msg.Content))
		for j, part := range msg.Content {
			parts[j] = deepCopyPart(part)
		}
		copied[i] = &ai.Message{
			Role:     msg.Role,
			Content:  parts,
			Metadata: shallowCopyMap(msg.Metadata),
		}
	}
	return copied
}

// deepCopyPart creates an independent copy of an ai.Part struct.
//
// Note on Input/Output fields: ToolRequest.Input and ToolResponse.Output
// are type `any` and copied by reference. This is acceptable because:
// 1. Genkit's renderMessages() only mutates msg.Content slice, not tool data
// 2. Tool inputs/outputs are typically JSON-serializable primitives
// If deep copy of these fields is needed, use encoding/json round-trip.
func deepCopyPart(p *ai.Part) *ai.Part {
	if p == nil {
		return nil
	}
	cp := &ai.Part{
		Kind:        p.Kind,
		ContentType: p.ContentType,
		Text:        p.Text,
		Custom:      shallowCopyMap(p.Custom),
		Metadata:    shallowCopyMap(p.Metadata),
	}
	if p.ToolRequest != nil {
		cp.ToolRequest = &ai.ToolRequest{
			Input: p.ToolRequest.Input, // Reference copy - see function doc
			Name:  p.ToolRequest.Name,
			Ref:   p.ToolRequest.Ref,
		}
	}
	if p.ToolResponse != nil {
		cp.ToolResponse = &ai.ToolResponse{
			Name:   p.ToolResponse.Name,
			Output: p.ToolResponse.Output, // Reference copy - see function doc
			Ref:    p.ToolResponse.Ref,
		}
	}
	if p.Resource != nil {
		cp.Resource = &ai.ResourcePart{Uri: p.Resource.Uri}
	}
	return cp
}

// shallowCopyMap copies map keys and values but not nested structures.
// Nested maps, slices, or pointers remain shared with the original.
func shallowCopyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	cp := make(map[string]any, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}
