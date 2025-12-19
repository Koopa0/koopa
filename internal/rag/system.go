// Package rag provides RAG (Retrieval-Augmented Generation) functionality.
// This file implements IndexSystemKnowledge for managing built-in knowledge
// about Agent capabilities, Golang best practices, and architecture principles.
package rag

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/plugins/postgresql"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IndexSystemKnowledge indexes all built-in system knowledge documents.
// Called once during application startup.
//
// Features:
//   - Uses fixed document IDs (e.g., "system:golang-errors")
//   - UPSERT behavior via delete-then-insert (Genkit DocStore doesn't support UPSERT)
//   - Returns count of successfully indexed documents
//
// Returns: (indexedCount, error)
// Error: returns error if indexing fails
func IndexSystemKnowledge(ctx context.Context, store *postgresql.DocStore, pool *pgxpool.Pool) (int, error) {
	docs := buildSystemKnowledgeDocs()

	// Extract document IDs for deletion (UPSERT emulation)
	ids := make([]string, 0, len(docs))
	for _, doc := range docs {
		if id, ok := doc.Metadata["id"].(string); ok {
			ids = append(ids, id)
		}
	}

	// Delete existing documents first (UPSERT emulation)
	// This is necessary because Genkit DocStore.Index() only does INSERT
	if err := deleteByIDs(ctx, pool, ids); err != nil {
		slog.Debug("failed to delete existing system knowledge (may not exist)", "error", err)
		// Continue - documents may not exist yet
	}

	if err := store.Index(ctx, docs); err != nil {
		return 0, fmt.Errorf("failed to index system knowledge: %w", err)
	}

	slog.Debug("system knowledge indexed", "count", len(docs))

	return len(docs), nil
}

// deleteByIDs deletes documents by their IDs.
// Used for UPSERT emulation since Genkit DocStore only supports INSERT.
func deleteByIDs(ctx context.Context, pool *pgxpool.Pool, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	// Use parameterized query to prevent SQL injection
	query := `DELETE FROM documents WHERE id = ANY($1)`
	_, err := pool.Exec(ctx, query, ids)
	if err != nil {
		return fmt.Errorf("deleting documents: %w", err)
	}
	return nil
}

// buildSystemKnowledgeDocs constructs all system knowledge documents.
func buildSystemKnowledgeDocs() []*ai.Document {
	var docs []*ai.Document

	// 1. Golang Style Guide
	docs = append(docs, buildGolangStyleDocs()...)

	// 2. Agent Capabilities
	docs = append(docs, buildCapabilitiesDocs()...)

	// 3. Architecture Principles
	docs = append(docs, buildArchitectureDocs()...)

	return docs
}

// buildGolangStyleDocs creates Golang best practices documents.
func buildGolangStyleDocs() []*ai.Document {
	return []*ai.Document{
		// Document 1: Error Handling
		ai.DocumentFromText(`# Golang Error Handling Best Practices

## Core Principles
- Always check errors immediately after function calls
- Use fmt.Errorf with %w for error wrapping (enables errors.Is/As)
- Avoid naked returns in error paths
- Return errors to callers, don't panic unless truly exceptional

## Examples
Good:
  result, err := doSomething()
  if err != nil {
      return fmt.Errorf("failed to do something: %w", err)
  }

Bad:
  result, _ := doSomething() // Ignoring errors

## Security
- Never expose internal error details to users
- Log full errors, return sanitized messages`,
			map[string]any{
				"id":          "system:golang-errors",
				"source_type": SourceTypeSystem,
				"category":    "golang",
				"topic":       "error-handling",
				"version":     "1.0",
			}),

		// Document 2: Concurrency Patterns
		ai.DocumentFromText(`# Golang Concurrency Best Practices

## Goroutines
- Always have a way to stop goroutines (context, done channel)
- Use WaitGroups for coordinating multiple goroutines
- Avoid goroutine leaks by ensuring all goroutines eventually exit

## Channels
- Close channels from sender side only
- Use select with context.Done() for cancellation
- Buffered channels for non-blocking sends

## Context
- Pass context as first parameter
- Use context.WithTimeout for operations with deadlines
- Never store context in struct fields (exception: short-lived request-scoped structs)

## Mutexes
- Keep critical sections small
- Use RWMutex when read-heavy workload
- Prefer channels over shared memory when possible`,
			map[string]any{
				"id":          "system:golang-concurrency",
				"source_type": SourceTypeSystem,
				"category":    "golang",
				"topic":       "concurrency",
				"version":     "1.0",
			}),

		// Document 3: Naming Conventions
		ai.DocumentFromText(`# Golang Naming Conventions

## Packages
- Short, lowercase, no underscores (e.g., httputil, not http_util)
- Singular form (e.g., encoding, not encodings)

## Interfaces
- One-method interfaces: name with -er suffix (Reader, Writer, Closer)
- Avoid "I" prefix (use Reader, not IReader)

## Getters/Setters
- No "Get" prefix for getters (use Owner(), not GetOwner())
- Use "Set" prefix for setters (SetOwner())

## Acronyms
- Keep consistent casing: URL, HTTP, ID (not Url, Http, Id)
- In names: use URLParser, not UrlParser

## Exported vs Unexported
- Exported: PascalCase (MyFunction, MyStruct)
- Unexported: camelCase (myFunction, myStruct)`,
			map[string]any{
				"id":          "system:golang-naming",
				"source_type": SourceTypeSystem,
				"category":    "golang",
				"topic":       "naming",
				"version":     "1.0",
			}),
	}
}

// buildCapabilitiesDocs creates Agent capabilities documents.
func buildCapabilitiesDocs() []*ai.Document {
	return []*ai.Document{
		// Document 4: Available Tools
		ai.DocumentFromText(`# Agent Available Tools

## File Operations
- readFile: Read file contents
- writeFile: Create or update file
- listFiles: List directory contents with glob patterns
- deleteFile: Remove file (requires confirmation)
- getFileInfo: Get file metadata

## System Operations
- currentTime: Get current timestamp
- executeCommand: Run shell commands (requires confirmation for destructive ops)
- getEnv: Read environment variables

## Network Operations
- httpGet: Fetch web content

## Knowledge Search
- searchHistory: Search conversation history
- searchDocuments: Search user-indexed documents (Notion pages, local files)
- searchSystemKnowledge: Search Agent's built-in knowledge

## Limitations
- File operations limited to current working directory
- Commands requiring sudo are blocked
- Network access: HTTP GET only (no POST/PUT)
- Cannot access system files (/etc, /sys, etc.)`,
			map[string]any{
				"id":          "system:agent-tools",
				"source_type": SourceTypeSystem,
				"category":    "capabilities",
				"topic":       "available-tools",
				"version":     "1.0",
			}),

		// Document 5: Best Practices
		ai.DocumentFromText(`# Agent Best Practices

## When to Use Tools
- searchHistory: When user asks "what did I say about X?"
- searchDocuments: When user asks about their notes/documents
- searchSystemKnowledge: When unsure about Golang conventions or Agent capabilities
- readFile before writeFile: Always read first to understand context

## Communication
- Be concise but informative
- Use code blocks for code snippets
- Explain what you're about to do before using destructive tools
- Ask for confirmation when ambiguous

## Error Handling
- If a tool fails, try alternative approaches
- Explain errors in user-friendly language
- Don't give up after first failure - retry with different parameters

## Security
- Never execute user-provided code without understanding it
- Always validate file paths before operations
- Sanitize command inputs to prevent injection`,
			map[string]any{
				"id":          "system:agent-best-practices",
				"source_type": SourceTypeSystem,
				"category":    "capabilities",
				"topic":       "best-practices",
				"version":     "1.0",
			}),
	}
}

// buildArchitectureDocs creates architecture principles documents.
func buildArchitectureDocs() []*ai.Document {
	return []*ai.Document{
		// Document 6: Design Principles
		ai.DocumentFromText(`# Koopa CLI Architecture Principles

## Dependency Injection
- Use Wire for compile-time DI
- Define interfaces in consumer packages (not provider packages)
- Accept interfaces, return structs

## Package Structure
- internal/agent: Core AI interaction logic
- internal/tools: Tool definitions and implementations
- internal/rag: Knowledge retrieval and indexing
- internal/session: Session persistence
- cmd: CLI commands and user interaction

## Error Handling
- Errors propagate up, logged at boundaries
- Use error wrapping (fmt.Errorf with %w)
- Graceful degradation when non-critical services fail

## Testing
- Unit tests for business logic
- Integration tests for cross-package interactions
- Use interfaces for mocking

## Security
- Principle of least privilege
- Input validation at boundaries
- Explicit user confirmation for destructive operations

## Concurrency
- Use context for cancellation
- Protect shared state with mutexes
- Goroutines must have cleanup mechanism`,
			map[string]any{
				"id":          "system:architecture-principles",
				"source_type": SourceTypeSystem,
				"category":    "architecture",
				"topic":       "design-principles",
				"version":     "1.0",
			}),
	}
}
