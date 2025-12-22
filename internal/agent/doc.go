// Package agent provides sentinel errors for the chat agent.
//
// # Overview
//
// This package provides shared error types for building conversational AI agents.
// The main implementation is in the chat subpackage.
//
// # Errors
//
// The package provides sentinel errors for consistent error handling:
//
//	agent.ErrInvalidSession   // Invalid session ID format
//	agent.ErrExecutionFailed  // LLM or tool execution failed
//
// # Usage
//
// The chat subpackage provides the Chat agent implementation:
//
//	import "github.com/koopa0/koopa/internal/agent/chat"
//
//	chatAgent, err := chat.New(chat.Config{
//	    Genkit:       g,
//	    Retriever:    retriever,
//	    SessionStore: sessionStore,
//	    Logger:       logger,
//	    Tools:        tools,
//	    MaxTurns:     10,
//	    RAGTopK:      5,
//	    Language:     "auto",
//	})
//
// See the chat subpackage for the complete implementation.
package agent
