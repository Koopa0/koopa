package chat

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/postgresql"
	"github.com/google/uuid"

	"github.com/koopa0/koopa-cli/internal/artifact"
	"github.com/koopa0/koopa-cli/internal/log"
	"github.com/koopa0/koopa-cli/internal/rag"
	"github.com/koopa0/koopa-cli/internal/session"
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
	Genkit        *genkit.Genkit
	Retriever     ai.Retriever // Genkit Retriever for RAG context
	SessionStore  *session.Store
	ArtifactStore *artifact.Store // Optional: nil = Canvas disabled
	Logger        log.Logger
	Tools         []ai.Tool // Pre-registered tools from RegisterXxxTools()

	// Configuration values
	// NOTE: LLM model is configured in prompts/koopa.prompt, not here
	MaxTurns int    // Maximum agentic loop turns
	RAGTopK  int    // Number of RAG documents to retrieve
	Language string // Response language preference
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

	// Dependencies (read-only after construction)
	g         *genkit.Genkit
	retriever ai.Retriever // Genkit Retriever for RAG context
	sessions  *session.Store
	artifacts *artifact.Store // Optional: nil = Canvas disabled
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

		// Dependencies
		g:         cfg.Genkit,
		retriever: cfg.Retriever,
		sessions:  cfg.SessionStore,
		artifacts: cfg.ArtifactStore, // Optional: nil = Canvas disabled
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
func (c *Chat) Execute(ctx context.Context, sessionID uuid.UUID, branch, input string) (*Response, error) {
	return c.ExecuteStream(ctx, sessionID, branch, input, false, nil)
}

// ExecuteStream runs the chat agent with optional streaming output.
// If callback is non-nil, it is called for each chunk of the response as it's generated.
// If callback is nil, the response is generated without streaming (equivalent to Execute).
// canvasEnabled tells the AI to output interactive content (code, markdown) for Canvas panel.
// The final response is always returned after generation completes.
func (c *Chat) ExecuteStream(ctx context.Context, sessionID uuid.UUID, branch, input string, canvasEnabled bool, callback StreamCallback) (*Response, error) {
	streaming := callback != nil
	c.logger.Debug("executing chat agent",
		"session_id", sessionID,
		"branch", branch,
		"streaming", streaming,
		"canvasEnabled", canvasEnabled)

	// Load session history
	history, err := c.sessions.LoadHistory(ctx, sessionID, branch)
	if err != nil {
		return nil, fmt.Errorf("failed to load history: %w", err)
	}

	// Generate response using unified core logic
	resp, err := c.generateResponse(ctx, input, history.Messages(), canvasEnabled, callback)
	if err != nil {
		return nil, err
	}

	responseText := resp.Text()

	if strings.TrimSpace(responseText) == "" {
		c.logger.Warn("model returned empty response",
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
	if err := c.sessions.AppendMessages(ctx, sessionID, branch, newMessages); err != nil {
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
// canvasEnabled is passed to the Dotprompt template for Canvas-specific instructions.
func (c *Chat) generateResponse(ctx context.Context, input string, historyMessages []*ai.Message, canvasEnabled bool, callback StreamCallback) (*ai.ModelResponse, error) {
	// Build messages: deep copy history and append current user input
	// CRITICAL: Deep copy is required to prevent DATA RACE in Genkit's renderMessages()
	// Genkit modifies msg.Content in-place, so concurrent executions sharing the same
	// message objects will race. We must copy each message, not just the slice.
	messages := deepCopyMessages(historyMessages)
	messages = append(messages, ai.NewUserMessage(ai.NewTextPart(input)))

	// Retrieve relevant documents for RAG context (graceful fallback on error)
	ragDocs := c.retrieveRAGContext(ctx, input)

	// Build execute options (using cached toolRefs and languagePrompt)
	opts := []ai.PromptExecuteOption{
		ai.WithInput(map[string]any{
			"language":      c.languagePrompt,
			"canvasEnabled": canvasEnabled,
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
		"canvasEnabled", canvasEnabled,
	)

	// Execute prompt
	resp, err := c.prompt.Execute(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("prompt execution failed: %w", err)
	}

	return resp, nil
}

// retrieveRAGContext retrieves relevant documents from the knowledge base.
// Returns empty slice on error (graceful degradation).
func (c *Chat) retrieveRAGContext(ctx context.Context, query string) []*ai.Document {
	// Skip RAG if topK is not configured or zero
	if c.ragTopK <= 0 {
		return nil
	}

	// Build retriever request with source_type filter for files (documents)
	req := &ai.RetrieverRequest{
		Query: ai.DocumentFromText(query, nil),
		Options: &postgresql.RetrieverOptions{
			Filter: "source_type = '" + rag.SourceTypeFile + "'",
			K:      c.ragTopK,
		},
	}

	// Retrieve documents
	resp, err := c.retriever.Retrieve(ctx, req)
	if err != nil {
		// Use Debug for expected errors (timeout, cancellation)
		// Use Warn for unexpected errors (DB issues, etc.) that ops should know about
		if ctx.Err() != nil {
			c.logger.Debug("RAG retrieval canceled (continuing without context)",
				"error", err,
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
// TODO: Remove when Genkit fixes the data race in renderMessages()
func deepCopyMessages(msgs []*ai.Message) []*ai.Message {
	if msgs == nil {
		return nil // Preserve nil vs empty slice semantics
	}
	copied := make([]*ai.Message, len(msgs))
	for i, msg := range msgs {
		parts := make([]*ai.Part, len(msg.Content))
		for j, part := range msg.Content {
			cp := *part
			parts[j] = &cp
		}
		copied[i] = &ai.Message{Role: msg.Role, Content: parts}
	}
	return copied
}
