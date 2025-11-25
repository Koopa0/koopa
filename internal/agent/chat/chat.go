package chat

import (
	"fmt"

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
)

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

// Execute runs the chat agent with the given input.
func (c *Chat) Execute(ctx agent.InvocationContext, input string) (*agent.Response, error) {
	c.logger.Info("executing chat agent",
		"invocation_id", ctx.InvocationID(),
		"session_id", ctx.SessionID(),
		"branch", ctx.Branch())

	// Load session history
	history, err := c.sessions.LoadHistory(ctx, ctx.SessionID(), ctx.Branch())
	if err != nil {
		return nil, fmt.Errorf("failed to load history: %w", err)
	}

	// Get previous messages from history
	historyMessages := history.Messages()

	// Build message list with current input
	messages := c.buildMessages(input, historyMessages)

	// Use configured model or default
	modelName := c.config.ModelName
	if modelName == "" {
		modelName = DefaultModel
	}

	// Prepare generation options with cached tool references
	generateOptions := []ai.GenerateOption{
		ai.WithModelName(modelName),
		ai.WithMessages(messages...),
		ai.WithTools(c.toolRefs...),
	}

	// Generate response using LLM
	resp, err := genkit.Generate(ctx, c.g, generateOptions...)
	if err != nil {
		return nil, fmt.Errorf("generation failed: %w", err)
	}

	responseText := resp.Text()

	// Update history with user input and response
	history.Add(input, responseText)

	// Save updated history to session store
	if err := c.sessions.SaveHistory(ctx, ctx.SessionID(), ctx.Branch(), history); err != nil {
		c.logger.Warn("failed to save history", "error", err)
	}

	// Return formatted response
	return &agent.Response{
		FinalText:    responseText,
		History:      history.Messages(),
		ToolRequests: resp.ToolRequests(),
	}, nil
}

// buildMessages constructs the message list for Genkit generation.
func (c *Chat) buildMessages(input string, history []*ai.Message) []*ai.Message {
	messages := []*ai.Message{}

	if history != nil {
		messages = append(messages, history...)
	}

	messages = append(messages, ai.NewUserMessage(ai.NewTextPart(input)))

	return messages
}

// emptyReadonlyContext is used for toolset registration.
type emptyReadonlyContext struct{}

func (e *emptyReadonlyContext) InvocationID() string       { return "" }
func (e *emptyReadonlyContext) Branch() string             { return "" }
func (e *emptyReadonlyContext) SessionID() agent.SessionID { return "" }
func (e *emptyReadonlyContext) AgentName() string          { return "" }
