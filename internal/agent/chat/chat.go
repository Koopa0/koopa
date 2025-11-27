package chat

import (
	"context"
	"fmt"
	"strings"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/log"
	"github.com/koopa0/koopa-cli/internal/rag"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/tools"
)

// Agent name and description constants
const (
	// Name is the unique identifier for the Chat agent.
	Name = "chat"

	// Description describes the Chat agent's capabilities.
	Description = "A general purpose chat agent that can help with various tasks using tools and knowledge base."

	// DefaultModel is the default LLM model when not configured.
	DefaultModel = "googleai/gemini-2.5-flash"

	// KoopaPromptName is the name of the Dotprompt file for the Chat agent.
	// This corresponds to prompts/koopa.prompt.
	KoopaPromptName = "koopa"
)

// StreamCallback is called for each chunk of streaming response.
// The chunk contains partial content that can be immediately displayed to the user.
// Return an error to abort the stream.
type StreamCallback func(ctx context.Context, chunk *ai.ModelResponseChunk) error

// Deps contains all required dependencies for Chat agent.
// These are mandatory and must be provided during construction.
type Deps struct {
	Config         *config.Config
	Genkit         *genkit.Genkit
	Retriever      *rag.Retriever
	SessionStore   *session.Store
	KnowledgeStore *knowledge.Store
	Logger         log.Logger
	Toolsets       []tools.Toolset
}

// Chat is Koopa's main conversational agent.
// It implements the agent.Agent interface and provides LLM-powered
// conversations with tool calling and knowledge base integration.
//
// Chat is stateless and uses dependency injection.
// Required dependencies are provided via Deps struct.
// Optional configuration is provided via functional options.
type Chat struct {
	config         *config.Config
	g              *genkit.Genkit
	retriever      *rag.Retriever
	sessions       *session.Store
	knowledgeStore *knowledge.Store
	logger         log.Logger
	toolsets       []tools.Toolset
	toolRefs       []ai.ToolRef // Cached tool references after registration
	prompt         ai.Prompt    // Cached Dotprompt instance (nil = use fallback Generate)
}

// New creates a new Chat agent with required dependencies.
//
// Example:
//
//	chat, err := chat.New(chat.Deps{
//	    Config:         cfg,
//	    Genkit:         g,
//	    Retriever:      retriever,
//	    SessionStore:   sessionStore,
//	    KnowledgeStore: knowledgeStore,
//	    Logger:         logger,
//	    Toolsets:       []tools.Toolset{fileToolset, systemToolset},
//	})
func New(deps Deps) (*Chat, error) {
	// Validate required dependencies
	if deps.Config == nil {
		return nil, fmt.Errorf("Deps.Config is required")
	}
	if deps.Genkit == nil {
		return nil, fmt.Errorf("Deps.Genkit is required")
	}
	if deps.Retriever == nil {
		return nil, fmt.Errorf("Deps.Retriever is required")
	}
	if deps.SessionStore == nil {
		return nil, fmt.Errorf("Deps.SessionStore is required")
	}
	if deps.KnowledgeStore == nil {
		return nil, fmt.Errorf("Deps.KnowledgeStore is required")
	}
	if deps.Logger == nil {
		return nil, fmt.Errorf("Deps.Logger is required")
	}
	if len(deps.Toolsets) == 0 {
		return nil, fmt.Errorf("Deps.Toolsets is required (at least one toolset)")
	}

	c := &Chat{
		config:         deps.Config,
		g:              deps.Genkit,
		retriever:      deps.Retriever,
		sessions:       deps.SessionStore,
		knowledgeStore: deps.KnowledgeStore,
		logger:         deps.Logger,
		toolsets:       deps.Toolsets,
	}

	// Register tools from all toolsets and cache references
	emptyCtx := &emptyReadonlyContext{}
	for _, ts := range c.toolsets {
		toolList, err := ts.Tools(emptyCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to get tools from toolset %s: %w", ts.Name(), err)
		}

		for _, t := range toolList {
			execTool, ok := t.(*tools.ExecutableTool)
			if !ok {
				return nil, fmt.Errorf("tool %s is not an ExecutableTool", t.Name())
			}

			genkitTool := genkit.DefineTool(
				c.g,
				execTool.Name(),
				execTool.Description(),
				execTool.Execute,
			)

			c.toolRefs = append(c.toolRefs, genkitTool)
		}
	}

	// Load Dotprompt (koopa.prompt) - REQUIRED
	c.prompt = genkit.LookupPrompt(c.g, KoopaPromptName)
	if c.prompt == nil {
		return nil, fmt.Errorf("dotprompt '%s' not found: ensure prompts directory is configured correctly", KoopaPromptName)
	}
	c.logger.Debug("loaded dotprompt successfully", "prompt_name", KoopaPromptName)

	return c, nil
}

// Name returns the agent name.
func (c *Chat) Name() string {
	return Name
}

// Description returns a description of the agent's capabilities.
func (c *Chat) Description() string {
	return Description
}

// SubAgents returns any sub-agents (none for this agent).
func (c *Chat) SubAgents() []agent.Agent {
	return nil
}

// Execute runs the chat agent with the given input (non-streaming).
// This is a convenience wrapper around ExecuteStream with nil callback.
func (c *Chat) Execute(ctx agent.InvocationContext, input string) (*agent.Response, error) {
	return c.ExecuteStream(ctx, input, nil)
}

// ExecuteStream runs the chat agent with optional streaming output.
// If callback is non-nil, it is called for each chunk of the response as it's generated.
// If callback is nil, the response is generated without streaming (equivalent to Execute).
// The final response is always returned after generation completes.
func (c *Chat) ExecuteStream(ctx agent.InvocationContext, input string, callback StreamCallback) (*agent.Response, error) {
	streaming := callback != nil
	c.logger.Debug("executing chat agent",
		"invocation_id", ctx.InvocationID(),
		"session_id", ctx.SessionID(),
		"branch", ctx.Branch(),
		"streaming", streaming)

	// Load session history
	history, err := c.sessions.LoadHistory(ctx, ctx.SessionID(), ctx.Branch())
	if err != nil {
		return nil, fmt.Errorf("failed to load history: %w", err)
	}

	// Get previous messages from history
	historyMessages := history.Messages()

	// Generate response using unified core logic
	resp, err := c.execute(ctx, input, historyMessages, callback)
	if err != nil {
		return nil, err
	}

	// Defensive check: execute should never return nil without error
	if resp == nil {
		return nil, fmt.Errorf("internal error: execute returned nil response without error")
	}

	responseText := resp.Text()

	if strings.TrimSpace(responseText) == "" {
		c.logger.Warn("model returned empty response",
			"invocation_id", ctx.InvocationID(),
			"session_id", ctx.SessionID())
		responseText = "I apologize, but I couldn't generate a response. Please try rephrasing your question."
	}

	// Update history with user input and response
	history.Add(input, responseText)

	// Save updated history to session store using AppendMessages (preferred)
	newMessages := []*ai.Message{
		ai.NewUserMessage(ai.NewTextPart(input)),
		ai.NewModelMessage(ai.NewTextPart(responseText)),
	}
	if err := c.sessions.AppendMessages(ctx, ctx.SessionID(), ctx.Branch(), newMessages); err != nil {
		c.logger.Error("failed to append messages to history", "error", err)
		// Don't fail the request, just log the error
	}

	// Return formatted response
	return &agent.Response{
		FinalText:    responseText,
		History:      history.Messages(),
		ToolRequests: resp.ToolRequests(),
	}, nil
}

// execute is the unified execution logic for both streaming and non-streaming modes.
// If callback is non-nil, streaming is enabled; otherwise, standard generation is used.
func (c *Chat) execute(ctx context.Context, input string, historyMessages []*ai.Message, callback StreamCallback) (*ai.ModelResponse, error) {
	// Build messages: history + current user input
	messages := append(historyMessages, ai.NewUserMessage(ai.NewTextPart(input)))

	// Retrieve relevant documents for RAG context (graceful fallback on error)
	ragDocs := c.retrieveRAGContext(ctx, input)

	language := c.resolveLanguage()

	messagesFn := func(_ context.Context, _ any) ([]*ai.Message, error) {
		return messages, nil
	}

	// Build execute options
	// MaxTurns ensures ReAct tool loop executes properly (default: 5)
	maxTurns := c.config.MaxTurns
	if maxTurns <= 0 {
		maxTurns = 5 // Fallback default
	}

	opts := []ai.PromptExecuteOption{
		ai.WithInput(map[string]any{
			"language": language,
		}),
		ai.WithMessagesFn(messagesFn),
		ai.WithTools(c.toolRefs...),
		ai.WithMaxTurns(maxTurns),
	}

	// Add RAG documents if available
	if len(ragDocs) > 0 {
		opts = append(opts, ai.WithDocs(ragDocs...))
	}

	// Add streaming callback if provided
	if callback != nil {
		opts = append(opts, ai.WithStreaming(callback))
	}

	// Execute prompt
	resp, err := c.prompt.Execute(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("prompt execution failed: %w", err)
	}

	return resp, nil
}

// resolveLanguage returns the language setting for prompt execution.
func (c *Chat) resolveLanguage() string {
	language := c.config.Language
	if language == "" || language == "auto" {
		return "the same language as the user's input (auto-detect)"
	}
	return language
}

// resolveModelName returns the model name to use for generation.
func (c *Chat) resolveModelName() string {
	if c.config.ModelName != "" {
		return c.config.ModelName
	}
	return DefaultModel
}

// retrieveRAGContext retrieves relevant documents from the knowledge base.
// Returns empty slice on error (graceful degradation).
func (c *Chat) retrieveRAGContext(ctx context.Context, query string) []*ai.Document {
	// Skip RAG if topK is not configured or zero
	topK := c.config.RAGTopK
	if topK <= 0 {
		return nil
	}

	// Retrieve documents
	docs, err := c.retriever.RetrieveDocuments(ctx, query, topK)
	if err != nil {
		c.logger.Debug("RAG retrieval failed (continuing without context)",
			"error", err,
			"query_length", len(query))
		return nil
	}

	if len(docs) > 0 {
		c.logger.Debug("retrieved RAG context",
			"document_count", len(docs),
			"query_length", len(query))
	}

	return docs
}

// emptyReadonlyContext is used for toolset registration.
type emptyReadonlyContext struct{}

func (e *emptyReadonlyContext) InvocationID() string       { return "" }
func (e *emptyReadonlyContext) Branch() string             { return "" }
func (e *emptyReadonlyContext) SessionID() agent.SessionID { return "" }
func (e *emptyReadonlyContext) AgentName() string          { return "" }
