// Package knowledge provides system knowledge indexing functionality.
// This file implements SystemKnowledgeIndexer for managing built-in knowledge
// about Agent capabilities, Golang best practices, and architecture principles.
package knowledge

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// SystemKnowledgeIndexer manages indexing of system knowledge documents.
// It provides pre-defined knowledge about Agent capabilities, coding standards,
// and architectural principles.
//
// Thread-safe: safe for concurrent use (protected by mu).
type SystemKnowledgeIndexer struct {
	store  *Store
	logger *slog.Logger
	mu     sync.Mutex // Protects IndexAll/ClearAll from concurrent calls
}

// NewSystemKnowledgeIndexer creates a new system knowledge indexer.
func NewSystemKnowledgeIndexer(store *Store, logger *slog.Logger) *SystemKnowledgeIndexer {
	if logger == nil {
		logger = slog.Default()
	}

	return &SystemKnowledgeIndexer{
		store:  store,
		logger: logger,
	}
}

// IndexAll indexes all default system knowledge documents.
// This method is called during application startup.
//
// Features:
//   - Uses fixed document IDs (e.g., "system:golang-errors")
//   - UPSERT behavior (updates if already exists)
//   - Returns count of successfully indexed documents
//   - Thread-safe (uses mutex)
//
// Returns: (indexedCount, error)
// Error: returns error if ALL documents failed to index
func (s *SystemKnowledgeIndexer) IndexAll(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	docs := s.buildSystemKnowledgeDocs()

	successCount := 0
	for _, doc := range docs {
		if err := s.store.Add(ctx, doc); err != nil {
			s.logger.Error("failed to index system knowledge",
				"doc_id", doc.ID,
				"error", err)
			// Continue indexing other documents
			continue
		}
		successCount++
	}

	// Use Debug level - this is an internal background operation
	s.logger.Debug("system knowledge indexed",
		"total", len(docs),
		"success", successCount,
		"failed", len(docs)-successCount)

	// Return error if all documents failed to prevent silent failures
	if successCount == 0 {
		return 0, fmt.Errorf("failed to index any system knowledge documents")
	}

	return successCount, nil
}

// ClearAll removes all system knowledge documents.
// Useful for testing and manual reindexing.
// Thread-safe (uses mutex).
func (s *SystemKnowledgeIndexer) ClearAll(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Use Search with large TopK and source_type filter to get all system documents
	// TopK=1000 is sufficient to cover all system knowledge documents (currently 6)
	results, err := s.store.Search(ctx, "system knowledge",
		WithTopK(1000),
		WithFilter("source_type", SourceTypeSystem))
	if err != nil {
		return fmt.Errorf("failed to search system documents: %w", err)
	}

	// Delete all found system documents
	deletedCount := 0
	for _, result := range results {
		if err := s.store.Delete(ctx, result.Document.ID); err != nil {
			s.logger.Warn("failed to delete system document",
				"id", result.Document.ID,
				"error", err)
			// Continue deleting other documents
			continue
		}
		deletedCount++
	}

	s.logger.Info("system knowledge cleared",
		"deleted", deletedCount,
		"failed", len(results)-deletedCount)

	return nil
}

// buildSystemKnowledgeDocs constructs all system knowledge documents.
func (s *SystemKnowledgeIndexer) buildSystemKnowledgeDocs() []Document {
	var docs []Document

	// 1. Golang Style Guide
	docs = append(docs, s.buildGolangStyleDocs()...)

	// 2. Agent Capabilities
	docs = append(docs, s.buildCapabilitiesDocs()...)

	// 3. Architecture Principles
	docs = append(docs, s.buildArchitectureDocs()...)

	return docs
}

// buildGolangStyleDocs creates Golang best practices documents.
func (*SystemKnowledgeIndexer) buildGolangStyleDocs() []Document {
	now := time.Now()

	return []Document{
		// Document 1: Error Handling
		{
			ID: "system:golang-errors",
			Content: `# Golang Error Handling Best Practices

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
- Log full errors, return sanitized messages
`,
			Metadata: map[string]string{
				"source_type": SourceTypeSystem,
				"category":    "golang",
				"topic":       "error-handling",
				"version":     "1.0",
			},
			CreateAt: now,
		},

		// Document 2: Concurrency Patterns
		{
			ID: "system:golang-concurrency",
			Content: `# Golang Concurrency Best Practices

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
- Prefer channels over shared memory when possible
`,
			Metadata: map[string]string{
				"source_type": SourceTypeSystem,
				"category":    "golang",
				"topic":       "concurrency",
				"version":     "1.0",
			},
			CreateAt: now,
		},

		// Document 3: Naming Conventions
		{
			ID: "system:golang-naming",
			Content: `# Golang Naming Conventions

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
- Unexported: camelCase (myFunction, myStruct)
`,
			Metadata: map[string]string{
				"source_type": SourceTypeSystem,
				"category":    "golang",
				"topic":       "naming",
				"version":     "1.0",
			},
			CreateAt: now,
		},
	}
}

// buildCapabilitiesDocs creates Agent capabilities documents.
func (*SystemKnowledgeIndexer) buildCapabilitiesDocs() []Document {
	now := time.Now()

	return []Document{
		// Document 4: Available Tools
		{
			ID: "system:agent-tools",
			Content: `# Agent Available Tools

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
- Cannot access system files (/etc, /sys, etc.)
`,
			Metadata: map[string]string{
				"source_type": SourceTypeSystem,
				"category":    "capabilities",
				"topic":       "available-tools",
				"version":     "1.0",
			},
			CreateAt: now,
		},

		// Document 5: Best Practices
		{
			ID: "system:agent-best-practices",
			Content: `# Agent Best Practices

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
- Sanitize command inputs to prevent injection
`,
			Metadata: map[string]string{
				"source_type": SourceTypeSystem,
				"category":    "capabilities",
				"topic":       "best-practices",
				"version":     "1.0",
			},
			CreateAt: now,
		},
	}
}

// buildArchitectureDocs creates architecture principles documents.
func (*SystemKnowledgeIndexer) buildArchitectureDocs() []Document {
	now := time.Now()

	return []Document{
		// Document 6: Design Principles
		{
			ID: "system:architecture-principles",
			Content: `# Koopa CLI Architecture Principles

## Dependency Injection
- Use Wire for compile-time DI
- Define interfaces in consumer packages (not provider packages)
- Accept interfaces, return structs

## Package Structure
- internal/agent: Core AI interaction logic
- internal/tools: Tool definitions and implementations
- internal/knowledge: Knowledge store and search
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
- Goroutines must have cleanup mechanism
`,
			Metadata: map[string]string{
				"source_type": SourceTypeSystem,
				"category":    "architecture",
				"topic":       "design-principles",
				"version":     "1.0",
			},
			CreateAt: now,
		},
	}
}
