// Package chat implements Koopa's main conversational agent.
//
// Chat is a stateless, LLM-powered agent that provides conversational interactions
// with tool calling and knowledge base integration. It uses the Google Genkit framework
// for LLM inference and tool orchestration.
//
// # Architecture
//
// The Chat agent follows a stateless design pattern with dependency injection:
//
//	InvocationContext (input)
//	     |
//	     v
//	Chat.ExecuteStream() or Chat.Execute()
//	     |
//	     +-- Load session history from SessionStore
//	     |
//	     +-- Build message list (history + user input)
//	     |
//	     +-- Call Genkit Generate with:
//	     |    - LLM model
//	     |    - Tool references (cached at initialization)
//	     |    - Message history
//	     |    - Optional: StreamCallback for real-time output
//	     |
//	     +-- Save updated history to SessionStore
//	     |
//	     v
//	Response (final text + tool requests + history)
//
// # Dependency Injection
//
// Chat requires dependencies via the Deps struct at construction time:
//
//	type Deps struct {
//	    Config         *config.Config
//	    Genkit         *genkit.Genkit
//	    Retriever      *rag.Retriever
//	    SessionStore   *session.Store
//	    KnowledgeStore *knowledge.Store
//	    Logger         log.Logger
//	    Toolsets       []tools.Toolset
//	}
//
// All fields are required and validated during construction.
//
// # Streaming Support
//
// Chat supports both streaming and non-streaming execution modes:
//
//   - Execute(): Non-streaming, returns complete response
//   - ExecuteStream(): Streaming with optional callback for real-time output
//
// For streaming, provide a StreamCallback function:
//
//	type StreamCallback func(ctx context.Context, chunk *ai.ModelResponseChunk) error
//
// The callback is invoked for each chunk of the response, enabling real-time
// display (typewriter effect) in CLI or SSE streaming in HTTP APIs.
//
// # Flow (Genkit Integration)
//
// The package provides a Genkit Flow for HTTP and observability:
//
//   - GetFlow(): Returns singleton streaming Flow (prevents re-registration panic)
//   - Flow supports both Run() and Stream() methods
//   - Stream() enables Server-Sent Events (SSE) for real-time responses
//
// Example Flow usage:
//
//	// Get singleton Flow (call once during initialization)
//	chatFlow := chat.GetFlow(g, chatAgent)
//
//	// Non-streaming
//	output, err := chatFlow.Run(ctx, chat.Input{Query: "Hello", SessionID: "..."})
//
//	// Streaming (for SSE)
//	for streamValue, err := range chatFlow.Stream(ctx, input) {
//	    if streamValue.Done {
//	        // Final output in streamValue.Output
//	    } else {
//	        // Partial chunk in streamValue.Stream.Text
//	    }
//	}
//
// # Tool Registration
//
// Tools are registered from toolsets during initialization:
//
//  1. For each toolset, get its available tools via Tools() method
//  2. Convert ExecutableTools to Genkit format using genkit.DefineTool
//  3. Cache tool references for reuse across invocations
//  4. Validate that all tools were registered successfully
//
// Tool references are cached to avoid re-registering on every Execute call.
//
// # Session Management
//
// Chat manages conversation history through the SessionStore:
//
//	LoadHistory: Retrieves previous messages for a session
//	AppendMessages: Persists new messages incrementally (preferred)
//
// Sessions are branch-aware, allowing isolated conversation contexts.
// History save failures are logged but don't fail the request.
//
// # Example Usage
//
//	// Create Chat agent with required dependencies
//	chatAgent, err := chat.New(chat.Deps{
//	    Config:         cfg,
//	    Genkit:         g,
//	    Retriever:      retriever,
//	    SessionStore:   sessionStore,
//	    KnowledgeStore: knowledgeStore,
//	    Logger:         slog.Default(),
//	    Toolsets:       []tools.Toolset{fileToolset, systemToolset},
//	})
//	if err != nil {
//	    return err
//	}
//
//	// Non-streaming execution
//	resp, err := chatAgent.Execute(invCtx, "What is the weather?")
//
//	// Streaming execution with callback
//	resp, err := chatAgent.ExecuteStream(invCtx, "What is the weather?",
//	    func(ctx context.Context, chunk *ai.ModelResponseChunk) error {
//	        fmt.Print(chunk.Text()) // Real-time output
//	        return nil
//	    })
//
// # Error Handling
//
// The package uses sentinel errors for categorization:
//
//   - agent.ErrInvalidSession: Invalid session ID format
//   - agent.ErrExecutionFailed: LLM or tool execution failed
//   - agent.ErrRateLimited: API rate limit exceeded
//   - agent.ErrModelUnavailable: Model temporarily unavailable
//
// Empty responses are handled with a fallback message to improve UX.
//
// # Testing
//
// Chat is designed for testability:
//
//   - Dependencies are concrete types with clear interfaces
//   - Stateless design eliminates test ordering issues
//   - Deps struct allows partial configuration for unit tests
//
// # Thread Safety
//
// Chat is safe for concurrent use. The underlying dependencies (SessionStore,
// KnowledgeStore, Genkit) must also be thread-safe.
package chat
