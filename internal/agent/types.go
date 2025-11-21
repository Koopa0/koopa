// Package agent provides type definitions and interfaces for the AI agent system.
//
// This file contains:
//   - Core interfaces (Generator, SessionStore, KnowledgeStore)
//   - Response types
//   - Functional options for Agent configuration
package agent

import (
	"context"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/session"
	"log/slog"
)

// Generator defines an interface for generating model responses,
// allowing for mocking in tests.
type Generator interface {
	Generate(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error)
}

// Response represents the complete result of an agent execution.
// Designed for synchronous, blocking execution following 建議.md architecture.
type Response struct {
	FinalText string        // Model's final text output
	History   []*ai.Message // Complete conversation history including all tool calls
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
	GetMessages(ctx context.Context, sessionID uuid.UUID, limit, offset int32) ([]*session.Message, error)

	// AddMessages adds multiple messages to a session in batch
	AddMessages(ctx context.Context, sessionID uuid.UUID, messages []*session.Message) error
}

// KnowledgeStore defines the minimal interface for knowledge operations needed by Agent.
// Following Go best practices: interfaces are defined by the consumer (agent), not the provider (knowledge package).
// This allows Agent to depend on abstraction rather than concrete implementation, improving testability.
//
// Design: Only includes methods actually used by Agent (Count, Add, Search), not the full knowledge.Store API.
// This follows the Interface Segregation Principle - clients should not depend on methods they don't use.
//
// Note: Search is needed by tools.KnowledgeSearcher interface (used in tools.RegisterTools).
type KnowledgeStore interface {
	// Count returns the number of documents matching the filter
	Count(ctx context.Context, filter map[string]string) (int, error)

	// Add adds a document to the knowledge store with automatic embedding generation
	Add(ctx context.Context, doc knowledge.Document) error

	// Search performs semantic search on knowledge documents
	Search(ctx context.Context, query string, opts ...knowledge.SearchOption) ([]knowledge.Result, error)
}

// genkitGenerator is the production implementation of the Generator interface.
type genkitGenerator struct {
	g *genkit.Genkit
}

// Generate calls the underlying genkit.Generate function.
func (gg *genkitGenerator) Generate(ctx context.Context, opts ...ai.GenerateOption) (*ai.ModelResponse, error) {
	return genkit.Generate(ctx, gg.g, opts...)
}

// Option is a functional option for configuring the Agent.
type Option func(*Agent)

// WithSessionStore sets the session store for the agent.
func WithSessionStore(store SessionStore) Option {
	return func(a *Agent) {
		a.sessionStore = store
	}
}

// WithKnowledgeStore sets the knowledge store for the agent.
func WithKnowledgeStore(store KnowledgeStore) Option {
	return func(a *Agent) {
		a.knowledgeStore = store
	}
}

// WithLogger sets the logger for the agent.
func WithLogger(logger *slog.Logger) Option {
	return func(a *Agent) {
		a.logger = logger
	}
}
