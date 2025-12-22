// Package session provides conversation history persistence.
//
// The session package manages conversation sessions and messages with PostgreSQL backend.
// It provides thread-safe storage for conversation history with concurrent message insertion
// and transaction-safe operations.
//
// # Overview
//
// A session represents a conversation context. Each session can contain multiple messages
// exchanged between user and model. The package handles persistence while the agent handles
// the conversation logic.
//
// Key responsibilities:
//
//   - Session lifecycle (create, retrieve, list, delete)
//   - Message persistence with sequential ordering
//   - Transaction-safe batch message insertion
//   - Concurrent access safety
//
// # Architecture
//
// Session and Message Organization:
//
//	Session (conversation context)
//	     |
//	     +-- Metadata (ID, title, model_name, created_at, updated_at)
//	     |
//	     v
//	Messages (ordered conversation)
//	     |
//	     +-- Message 1 (role: "user")
//	     +-- Message 2 (role: "model")
//	     +-- Message 3 (role: "user")
//	     +-- ...
//
// Messages are ordered by sequence number within a session, ensuring
// consistent retrieval and reconstruction of conversation context.
//
// # Session Management
//
// The Store type provides session operations:
//
//	CreateSession(ctx, title, modelName, systemPrompt)  - Create new session
//	GetSession(ctx, sessionID)                          - Retrieve session
//	ListSessions(ctx, limit, offset)                   - List sessions with pagination
//	DeleteSession(ctx, sessionID)                      - Delete session and messages
//
// Sessions store optional metadata:
//
//   - Title: User-friendly name
//   - ModelName: LLM model used for this session
//   - SystemPrompt: Custom system instructions
//   - MessageCount: Total number of messages (cached for efficiency)
//
// # Message Persistence
//
// The Store provides message operations:
//
//	AddMessages(ctx, sessionID, messages)  - Batch insert with transaction safety
//	GetMessages(ctx, sessionID, limit, offset) - Retrieve messages with pagination
//
// Messages are stored with:
//
//   - Role: "user", "model", or "tool"
//   - Content: Array of ai.Part (serialized as JSONB)
//   - SequenceNumber: Sequential ordering within session
//   - CreatedAt: Timestamp
//
// # Transaction Safety
//
// AddMessages provides ACID guarantees for batch message insertion:
//
//  1. Lock session row (SELECT ... FOR UPDATE)
//  2. Get current max sequence number
//  3. Insert messages in batch with next sequence numbers
//  4. Update session metadata (message_count, updated_at)
//  5. Commit transaction atomically
//
// If any step fails, the entire transaction rolls back, ensuring consistency.
// Session locking prevents race conditions in concurrent scenarios.
//
// # Chat Agent Integration
//
// The Store provides methods for integration with the Chat agent:
//
//	GetHistory(ctx, sessionID) - Get conversation history for agent
//	AppendMessages(ctx, sessionID, messages) - Persist conversation messages
//
// Following Go standard library conventions (similar to database/sql returning *sql.DB),
// consumers use *session.Store directly instead of defining separate interfaces.
// Testability is achieved via the internal Querier interface (for mocking database operations).
//
// # Database Backend
//
// The session store requires PostgreSQL with the following schema:
//
//	sessions table:
//	    id             UUID PRIMARY KEY
//	    title          TEXT
//	    model_name     TEXT
//	    system_prompt  TEXT
//	    message_count  INT32
//	    created_at     TIMESTAMPTZ
//	    updated_at     TIMESTAMPTZ
//
//	session_messages table:
//	    id             UUID PRIMARY KEY
//	    session_id     UUID FOREIGN KEY (CASCADE)
//	    role           TEXT (user|model|tool)
//	    content        JSONB (ai.Part array)
//	    sequence_number INT32
//	    created_at     TIMESTAMPTZ
//
// # Example Usage
//
//	package main
//
//	import (
//	    "context"
//	    "github.com/firebase/genkit/go/ai"
//	    "github.com/jackc/pgx/v5/pgxpool"
//	    "github.com/koopa0/koopa/internal/session"
//	    "log/slog"
//	)
//
//	func main() {
//	    ctx := context.Background()
//
//	    // Connect to PostgreSQL
//	    dbPool, _ := pgxpool.New(ctx, "postgresql://...")
//	    defer dbPool.Close()
//
//	    // Create session store
//	    store := session.New(sqlc.New(dbPool), dbPool, slog.Default())
//
//	    // Create a new session
//	    sess, err := store.CreateSession(ctx, "My Conversation", "gemini-pro", "")
//	    if err != nil {
//	        panic(err)
//	    }
//	    println("Session ID:", sess.ID)
//
//	    // Add messages to session
//	    messages := []*session.Message{
//	        {
//	            Role: session.RoleUser,
//	            Content: []*ai.Part{ai.NewTextPart("Hello!")},
//	        },
//	        {
//	            Role: session.RoleModel,
//	            Content: []*ai.Part{ai.NewTextPart("Hi there!")},
//	        },
//	    }
//
//	    err = store.AddMessages(ctx, sess.ID, messages)
//	    if err != nil {
//	        panic(err)
//	    }
//
//	    // Retrieve messages
//	    retrieved, _ := store.GetMessages(ctx, sess.ID, 100, 0)
//	    println("Retrieved", len(retrieved), "messages")
//
//	    // Load history for agent
//	    history, _ := store.GetHistory(ctx, sess.ID)
//	    println("History messages:", len(history.Messages()))
//
//	    // List all sessions
//	    sessions, _ := store.ListSessions(ctx, 10, 0)
//	    println("Total sessions:", len(sessions))
//	}
//
// # Concurrency and Race Conditions
//
// The Store is designed to handle concurrent access safely:
//
//   - Session locking (SELECT ... FOR UPDATE) prevents concurrent modifications
//   - Transactions ensure atomicity of batch operations
//   - PostgreSQL isolation levels handle concurrent reads
//   - No shared state in Go code (all state in database)
//
// However, callers should avoid concurrent modifications to the same session
// to prevent transaction conflicts and retries.
//
// # Pagination
//
// All list operations support limit/offset pagination:
//
//   - ListSessions(ctx, limit=10, offset=0)  // First 10 sessions
//   - GetMessages(ctx, sessionID, limit=50, offset=0) // First 50 messages
//
// Sessions are ordered by updated_at descending (most recent first).
// Messages are ordered by sequence_number ascending (earliest first).
//
// # Error Handling
//
// The Store propagates database errors with context:
//
//   - "failed to create session: ..." - Creation failures
//   - "failed to get session ...: ..." - Retrieval failures
//   - "failed to lock session: ..." - Concurrency issues
//   - "failed to insert message ...: ..." - Message insertion failures
//   - "failed to unmarshal message content: ..." - Deserialization errors (skipped)
//
// Malformed messages are skipped during retrieval, allowing resilience
// to schema changes.
//
// # Testing
//
// The session package is designed for testability:
//
//   - Store accepts Querier interface for mock database
//   - New() accepts interface, pass mock querier directly for tests
//   - Integration tests use real PostgreSQL database
//   - Supports non-transactional mode for mock testing
//
// # Thread Safety
//
// The Store is thread-safe for concurrent use:
//
//   - All database operations use connection pool
//   - PostgreSQL handles concurrent access safely
//   - No shared state in Go code
//   - Transactions provide isolation
package session
