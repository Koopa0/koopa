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
//	Chat.Execute()
//	     |
//	     +-- Load session history from SessionStore
//	     |
//	     +-- Build message list (history + user input)
//	     |
//	     +-- Call Genkit Generate with:
//	     |    - LLM model
//	     |    - Tool references (cached at initialization)
//	     |    - Message history
//	     |
//	     +-- Save updated history to SessionStore
//	     |
//	     v
//	Response (final text + tool requests + history)
//
// # Dependency Injection
//
// Chat requires the following dependencies at construction time:
//
//   - Genkit instance: For LLM inference and tool orchestration
//   - Retriever: For knowledge base integration (RAG)
//   - SessionStore: For loading/saving conversation history
//   - KnowledgeStore: For semantic search operations
//   - Config: For model selection and generation parameters
//   - Logger: For structured logging
//   - Toolsets: At least one tool provider (File, System, Network, etc.)
//
// All dependencies are provided via functional options (WithXXX methods) following
// Go's functional options pattern. This makes dependencies explicit and enables
// easy testing with mock implementations.
//
// # Tool Registration
//
// Tools are registered from toolsets during initialization:
//
//  1. For each toolset, get its available tools
//  2. Convert tools to Genkit format using genkit.DefineTool
//  3. Cache tool references for reuse across invocations
//  4. Validate that all tools were registered successfully
//
// Tool references are cached to avoid re-registering on every Execute call,
// improving performance for high-throughput scenarios.
//
// # Session Management
//
// Chat manages conversation history through the SessionStore interface:
//
//	LoadHistory: Retrieves previous messages for a session
//	SaveHistory: Persists new messages to the session (currently a no-op)
//
// Sessions are branch-aware, allowing isolated conversation contexts.
// The CLI application layer is responsible for calling AddMessages for persistence.
//
// # RAG Integration
//
// Knowledge base integration is optional but recommended:
//
//   - Retriever provides access to semantic search
//   - Can be used to augment prompts with relevant context
//   - Supports multiple knowledge sources (conversations, files, system knowledge)
//
// # Example Usage
//
//	package main
//
//	import (
//	    "context"
//	    "github.com/firebase/genkit/go/genkit"
//	    "github.com/firebase/genkit/go/plugins/googlegenai"
//	    "github.com/koopa0/koopa-cli/internal/agent/chat"
//	    "github.com/koopa0/koopa-cli/internal/tools"
//	    "log/slog"
//	)
//
//	func main() {
//	    ctx := context.Background()
//
//	    // Initialize Genkit with Google AI plugin
//	    g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))
//
//	    // Create Chat agent with dependencies
//	    agent, err := chat.New(
//	        chat.WithGenkit(g),
//	        chat.WithSessionStore(sessionStore),
//	        chat.WithKnowledgeStore(knowledgeStore),
//	        chat.WithRetriever(retriever),
//	        chat.WithToolsets(fileToolset, systemToolset),
//	        chat.WithLogger(slog.Default()),
//	    )
//	    if err != nil {
//	        panic(err)
//	    }
//
//	    // Execute the chat agent
//	    resp, err := agent.Execute(invocationContext, "What is the weather?")
//	    if err != nil {
//	        panic(err)
//	    }
//
//	    println(resp.FinalText)
//	}
//
// # Flow Definition
//
// The DefineFlow method exposes the Chat agent as a Genkit flow with:
//
//   - Input validation and type safety
//   - Structured error handling
//   - Observability through Genkit DevUI
//   - HTTP endpoint exposure
//
// The flow acts as a lightweight wrapper delegating to Chat.Execute.
//
// # Testing
//
// Chat is designed for testability:
//
//   - Dependencies are interfaces, enabling mock implementations
//   - Stateless design eliminates test ordering issues
//   - Functional options allow partial configuration for unit tests
//
// # Thread Safety
//
// Chat is safe for concurrent use. The underlying dependencies (SessionStore,
// KnowledgeStore, Genkit) must also be thread-safe.
package chat
