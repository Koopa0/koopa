package session

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/sqlc"
)

// Querier defines the interface for database operations on sessions and messages.
// Following Go best practices: interfaces are defined by the consumer, not the provider.
//
// This interface allows Store to depend on abstraction rather than concrete implementation,
// improving testability and flexibility.
type Querier interface {
	// Session operations
	CreateSession(ctx context.Context, arg sqlc.CreateSessionParams) (sqlc.Session, error)
	GetSession(ctx context.Context, id pgtype.UUID) (sqlc.Session, error)
	ListSessions(ctx context.Context, arg sqlc.ListSessionsParams) ([]sqlc.Session, error)
	UpdateSessionUpdatedAt(ctx context.Context, arg sqlc.UpdateSessionUpdatedAtParams) error
	DeleteSession(ctx context.Context, id pgtype.UUID) error
	LockSession(ctx context.Context, id pgtype.UUID) (pgtype.UUID, error) // P1-2: Lock session for concurrent safety

	// Message operations
	AddMessage(ctx context.Context, arg sqlc.AddMessageParams) error
	GetMessages(ctx context.Context, arg sqlc.GetMessagesParams) ([]sqlc.SessionMessage, error)
	GetMaxSequenceNumber(ctx context.Context, sessionID pgtype.UUID) (int32, error)
}

// Store manages session persistence with PostgreSQL backend.
// It handles conversation history storage and retrieval.
//
// Store is safe for concurrent use by multiple goroutines.
type Store struct {
	querier Querier
	pool    *pgxpool.Pool // Database pool for transaction support
	logger  *slog.Logger
}

// New creates a new Store instance.
//
// Parameters:
//   - querier: Database querier implementing Querier interface
//   - pool: PostgreSQL connection pool (for transaction support, can be nil for tests)
//   - logger: Logger for debugging (nil = use default)
//
// Example (production with Wire):
//
//	store := session.New(sqlc.New(dbPool), dbPool, slog.Default())
//
// Example (testing with mock):
//
//	store := session.New(mockQuerier, nil, slog.Default())
func New(querier Querier, pool *pgxpool.Pool, logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}

	return &Store{
		querier: querier,
		pool:    pool,
		logger:  logger,
	}
}

// CreateSession creates a new conversation session.
//
// Parameters:
//   - ctx: Context for the operation
//   - title: Session title (empty string = no title)
//   - modelName: Model name used for this session (empty string = default)
//   - systemPrompt: System prompt for this session (empty string = default)
//
// Returns:
//   - *Session: Created session with generated UUID
//   - error: If creation fails
func (s *Store) CreateSession(ctx context.Context, title, modelName, systemPrompt string) (*Session, error) {
	// Convert empty strings to nil for nullable fields
	var titlePtr, modelNamePtr, systemPromptPtr *string
	if title != "" {
		titlePtr = &title
	}
	if modelName != "" {
		modelNamePtr = &modelName
	}
	if systemPrompt != "" {
		systemPromptPtr = &systemPrompt
	}

	sqlcSession, err := s.querier.CreateSession(ctx, sqlc.CreateSessionParams{
		Title:        titlePtr,
		ModelName:    modelNamePtr,
		SystemPrompt: systemPromptPtr,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	session := s.sqlcSessionToSession(sqlcSession)
	s.logger.Debug("created session", "id", session.ID, "title", session.Title)
	return session, nil
}

// GetSession retrieves a session by ID.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: UUID of the session to retrieve
//
// Returns:
//   - *Session: Retrieved session
//   - error: If session not found or retrieval fails
func (s *Store) GetSession(ctx context.Context, sessionID uuid.UUID) (*Session, error) {
	sqlcSession, err := s.querier.GetSession(ctx, uuidToPgUUID(sessionID))
	if err != nil {
		return nil, fmt.Errorf("failed to get session %s: %w", sessionID, err)
	}

	return s.sqlcSessionToSession(sqlcSession), nil
}

// ListSessions lists sessions with pagination, ordered by updated_at descending.
//
// Parameters:
//   - ctx: Context for the operation
//   - limit: Maximum number of sessions to return
//   - offset: Number of sessions to skip (for pagination)
//
// Returns:
//   - []*Session: List of sessions
//   - error: If listing fails
func (s *Store) ListSessions(ctx context.Context, limit, offset int32) ([]*Session, error) {
	sqlcSessions, err := s.querier.ListSessions(ctx, sqlc.ListSessionsParams{
		ResultLimit:  limit,
		ResultOffset: offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	sessions := make([]*Session, 0, len(sqlcSessions))
	for _, ss := range sqlcSessions {
		sessions = append(sessions, s.sqlcSessionToSession(ss))
	}

	s.logger.Debug("listed sessions", "count", len(sessions), "limit", limit, "offset", offset)
	return sessions, nil
}

// DeleteSession deletes a session and all its messages (CASCADE).
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: UUID of the session to delete
//
// Returns:
//   - error: If deletion fails
func (s *Store) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	if err := s.querier.DeleteSession(ctx, uuidToPgUUID(sessionID)); err != nil {
		return fmt.Errorf("failed to delete session %s: %w", sessionID, err)
	}

	s.logger.Debug("deleted session", "id", sessionID)
	return nil
}

// AddMessages adds multiple messages to a session in batch.
// This is more efficient than adding messages one by one.
//
// All operations are wrapped in a database transaction to ensure atomicity.
// If any operation fails, all changes are rolled back.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: UUID of the session to add messages to
//   - messages: Slice of messages to add
//
// Returns:
//   - error: If adding messages fails
//
// Note: Messages will be assigned sequential sequence numbers automatically.
func (s *Store) AddMessages(ctx context.Context, sessionID uuid.UUID, messages []*Message) error {
	if len(messages) == 0 {
		return nil
	}

	// If pool is nil (testing with mock), use non-transactional mode
	if s.pool == nil {
		return s.addMessagesNonTransactional(ctx, sessionID, messages)
	}

	// Begin transaction for atomicity
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	// Rollback if not committed - log any rollback errors for debugging
	defer func() {
		if err := tx.Rollback(ctx); err != nil {
			s.logger.Debug("transaction rollback (may be already committed)", "error", err)
		}
	}()

	// Create querier for this transaction
	txQuerier := sqlc.New(tx)

	// 0. Lock session row to prevent concurrent modifications (P1-2 fix)
	// This SELECT ... FOR UPDATE ensures that only one transaction can modify
	// this session at a time, preventing race conditions on sequence numbers
	_, err = txQuerier.LockSession(ctx, uuidToPgUUID(sessionID))
	if err != nil {
		return fmt.Errorf("failed to lock session: %w", err)
	}

	// 1. Get current max sequence number within transaction
	maxSeq, err := txQuerier.GetMaxSequenceNumber(ctx, uuidToPgUUID(sessionID))
	if err != nil {
		// If session doesn't exist yet or no messages, start from 0
		s.logger.Debug("no existing messages, starting from sequence 0",
			"session_id", sessionID)
		maxSeq = 0
	}

	// 2. Insert messages in batch within transaction
	for i, msg := range messages {
		// Validate Content slice for nil pointers (P2 quality improvement)
		for j, part := range msg.Content {
			if part == nil {
				return fmt.Errorf("message %d has nil content at index %d", i, j)
			}
		}

		// Marshal ai.Part slice to JSON
		contentJSON, err := json.Marshal(msg.Content)
		if err != nil {
			// Transaction will be rolled back by defer
			return fmt.Errorf("failed to marshal message content at index %d: %w", i, err)
		}

		// Calculate sequence number (maxSeq is now int32 from sqlc)
		// Safe conversion: loop index i is bounded by len(messages) which is checked by database constraints
		seqNum := maxSeq + int32(i) + 1 // #nosec G115 -- i is loop index bounded by slice length

		if err = txQuerier.AddMessage(ctx, sqlc.AddMessageParams{
			SessionID:      uuidToPgUUID(sessionID),
			Role:           msg.Role,
			Content:        contentJSON,
			SequenceNumber: seqNum,
		}); err != nil {
			// Transaction will be rolled back by defer
			return fmt.Errorf("failed to insert message %d: %w", i, err)
		}
	}

	// 3. Update session's updated_at and message_count within transaction
	// Safe conversion: len(messages) is bounded by practical limits (< millions)
	newCount := maxSeq + int32(len(messages)) // #nosec G115 -- len bounded by practical message limits
	if err = txQuerier.UpdateSessionUpdatedAt(ctx, sqlc.UpdateSessionUpdatedAtParams{
		MessageCount: &newCount,
		SessionID:    uuidToPgUUID(sessionID),
	}); err != nil {
		// Transaction will be rolled back by defer
		return fmt.Errorf("failed to update session metadata: %w", err)
	}

	// 4. Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	s.logger.Debug("added messages", "session_id", sessionID, "count", len(messages))
	return nil
}

// addMessagesNonTransactional adds messages without transaction (for testing with mocks).
// This is a fallback for when pool is nil.
//
// This function should ONLY be used in:
//   - Unit tests with mock queriers
//   - Single-threaded test scenarios
//   - Contexts where external synchronization is guaranteed
//
// For production use with concurrent access, always use AddMessages with a real database pool.
func (s *Store) addMessagesNonTransactional(ctx context.Context, sessionID uuid.UUID, messages []*Message) error {
	// 1. Get current max sequence number
	maxSeq, err := s.querier.GetMaxSequenceNumber(ctx, uuidToPgUUID(sessionID))
	if err != nil {
		s.logger.Debug("no existing messages, starting from sequence 0",
			"session_id", sessionID)
		maxSeq = 0
	}

	// 2. Insert messages in batch
	for i, msg := range messages {
		// Validate Content slice for nil pointers (P2 quality improvement)
		for j, part := range msg.Content {
			if part == nil {
				return fmt.Errorf("message %d has nil content at index %d", i, j)
			}
		}

		// Marshal ai.Part slice to JSON
		contentJSON, err := json.Marshal(msg.Content)
		if err != nil {
			return fmt.Errorf("failed to marshal message content at index %d: %w", i, err)
		}

		// Calculate sequence number (maxSeq is now int32 from sqlc)
		// Safe conversion: loop index i is bounded by len(messages) which is checked by database constraints
		seqNum := maxSeq + int32(i) + 1 // #nosec G115 -- i is loop index bounded by slice length

		if err = s.querier.AddMessage(ctx, sqlc.AddMessageParams{
			SessionID:      uuidToPgUUID(sessionID),
			Role:           msg.Role,
			Content:        contentJSON,
			SequenceNumber: seqNum,
		}); err != nil {
			return fmt.Errorf("failed to insert message %d: %w", i, err)
		}
	}

	// 3. Update session's updated_at and message_count
	newCount := maxSeq + int32(len(messages)) // #nosec G115 -- len bounded by practical message limits
	if err = s.querier.UpdateSessionUpdatedAt(ctx, sqlc.UpdateSessionUpdatedAtParams{
		MessageCount: &newCount,
		SessionID:    uuidToPgUUID(sessionID),
	}); err != nil {
		return fmt.Errorf("failed to update session metadata: %w", err)
	}

	s.logger.Debug("added messages (non-transactional)", "session_id", sessionID, "count", len(messages))
	return nil
}

// GetMessages retrieves messages for a session with pagination.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: UUID of the session
//   - limit: Maximum number of messages to return
//   - offset: Number of messages to skip (for pagination)
//
// Returns:
//   - []*Message: List of messages ordered by sequence number ascending
//   - error: If retrieval fails
func (s *Store) GetMessages(ctx context.Context, sessionID uuid.UUID, limit, offset int32) ([]*Message, error) {
	sqlcMessages, err := s.querier.GetMessages(ctx, sqlc.GetMessagesParams{
		SessionID:    uuidToPgUUID(sessionID),
		ResultLimit:  limit,
		ResultOffset: offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get messages for session %s: %w", sessionID, err)
	}

	messages := make([]*Message, 0, len(sqlcMessages))
	for _, sm := range sqlcMessages {
		msg, err := s.sqlcMessageToMessage(sm)
		if err != nil {
			s.logger.Warn("failed to unmarshal message content",
				"message_id", pgUUIDToUUID(sm.ID),
				"error", err)
			continue // Skip malformed messages
		}
		messages = append(messages, msg)
	}

	s.logger.Debug("retrieved messages", "session_id", sessionID, "count", len(messages))
	return messages, nil
}

// LoadHistory retrieves the conversation history for a session.
// Used by chat.Chat agent for session management.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: agent.SessionID (UUID string)
//   - branch: Branch name (currently ignored, defaults to main)
//
// Returns:
//   - *agent.History: Conversation history
//   - error: If retrieval fails
func (s *Store) LoadHistory(ctx context.Context, sessionID agent.SessionID, branch string) (*agent.History, error) {
	// Parse SessionID to UUID
	id, err := uuid.Parse(string(sessionID))
	if err != nil {
		return nil, fmt.Errorf("invalid session ID: %w", err)
	}

	// Retrieve all messages (up to a reasonable limit, e.g., 1000)
	// TODO: Implement proper pagination or sliding window if history is too long
	messages, err := s.GetMessages(ctx, id, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to load history: %w", err)
	}

	// Convert to ai.Message
	aiMessages := make([]*ai.Message, len(messages))
	for i, msg := range messages {
		aiMessages[i] = &ai.Message{
			Content: msg.Content,
			Role:    ai.Role(msg.Role),
		}
	}

	// Create History from messages
	return agent.NewHistoryFromMessages(aiMessages), nil
}

// SaveHistory saves the conversation history for a session.
// Used by chat.Chat agent for session management.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: agent.SessionID (UUID string)
//   - branch: Branch name (currently ignored)
//   - history: Conversation history
//
// Returns:
//   - error: If saving fails
func (s *Store) SaveHistory(ctx context.Context, sessionID agent.SessionID, branch string, history *agent.History) error {
	// In the current architecture, we append new messages rather than replacing history.
	// However, the interface implies saving the *state*.
	// Since we are stateless, we should only be adding *new* messages.
	// But SaveHistory is called with the *full* history or *new* messages?
	// The agent.History object contains ALL messages.
	// We need to identify which ones are new.
	//
	// OPTIMIZATION: For now, we assume the caller (Agent) is responsible for
	// managing what to save, or we only save the *last* message if we are tracking state.
	//
	// BUT, the Agent is stateless. It receives history, generates response, and returns.
	// The *Caller* (CLI) is responsible for saving the *new* user message and the *new* model response.
	//
	// Wait, if the Agent is stateless, why does it need SaveHistory?
	// Ah, the SessionStore interface is used by the Agent to *load* history for context.
	// Does the Agent *save* history?
	// In `agent.Execute`, we might want to save the response?
	//
	// If the Agent is truly stateless and the CLI handles persistence, then Agent shouldn't call SaveHistory.
	// The CLI calls `session.AddMessages`.
	//
	// However, to satisfy the interface, we implement it.
	// We will assume for now that we don't need to save anything here if the CLI handles it.
	// OR, if the Agent *does* call it, we need to handle it.
	//
	// Let's implement it by checking if messages exist? No, that's expensive.
	//
	// Actually, looking at `cmd/cmd.go`, the CLI handles `AddMessages`.
	// The `SessionStore` interface in `agent` might be for *internal* agent use (e.g. if agent manages memory).
	// But we moved memory out.
	//
	// So `SaveHistory` might be unused by `Chat` agent?
	// Let's check `agent.go`.
	// `Chat` agent DOES NOT call `SaveHistory`.
	// It only calls `LoadHistory` in `Execute` (via `buildMessages`? No, `Execute` takes `InvocationContext` which has `SessionID`).
	//
	// Wait, `Chat.Execute` implementation:
	// It loads history using `a.sessions.LoadHistory`.
	// It does NOT save history.
	//
	// So `SaveHistory` is technically not used by `Chat` agent logic, but required by interface.
	// We can leave it as a no-op or implement it for completeness.
	//
	// Implementation:
	// If we wanted to support saving from Agent, we'd need to know which messages are new.
	// Since we don't, and `Chat` doesn't call it, we can just return nil.
	//
	// BUT, `agent_test.go` or other tests might use it.
	// Let's implement a simple version that appends *all* messages? No, that duplicates.
	//
	// Let's return nil for now, as `Chat` agent delegates persistence to the caller (CLI).
	// The CLI uses `session.AddMessages`.

	// Parse SessionID to UUID
	id, err := uuid.Parse(string(sessionID))
	if err != nil {
		return fmt.Errorf("invalid session ID: %w", err)
	}

	// Get current messages from history
	aiMessages := history.Messages()
	if len(aiMessages) == 0 {
		return nil
	}

	// Load existing messages to determine which are new
	existingMessages, err := s.GetMessages(ctx, id, 1000, 0)
	if err != nil {
		// If session has no messages yet, that's fine
		s.logger.Debug("no existing messages found", "session_id", sessionID)
		existingMessages = nil
	}

	// Only save messages that don't already exist (compare by count)
	existingCount := len(existingMessages)
	if len(aiMessages) <= existingCount {
		// No new messages to save
		return nil
	}

	// Convert new ai.Messages to session.Messages
	newMessages := make([]*Message, 0, len(aiMessages)-existingCount)
	for i := existingCount; i < len(aiMessages); i++ {
		msg := aiMessages[i]
		newMessages = append(newMessages, &Message{
			Role:    string(msg.Role),
			Content: msg.Content,
		})
	}

	// Add new messages
	if len(newMessages) > 0 {
		if err := s.AddMessages(ctx, id, newMessages); err != nil {
			return fmt.Errorf("failed to add messages: %w", err)
		}
	}

	return nil
}

// sqlcSessionToSession converts sqlc.Session to Session (application type).
func (s *Store) sqlcSessionToSession(ss sqlc.Session) *Session {
	session := &Session{
		ID:        pgUUIDToUUID(ss.ID),
		CreatedAt: ss.CreatedAt.Time,
		UpdatedAt: ss.UpdatedAt.Time,
	}

	if ss.Title != nil {
		session.Title = *ss.Title
	}
	if ss.ModelName != nil {
		session.ModelName = *ss.ModelName
	}
	if ss.SystemPrompt != nil {
		session.SystemPrompt = *ss.SystemPrompt
	}
	if ss.MessageCount != nil {
		session.MessageCount = int(*ss.MessageCount)
	}

	return session
}

// sqlcMessageToMessage converts sqlc.SessionMessage to Message (application type).
func (s *Store) sqlcMessageToMessage(sm sqlc.SessionMessage) (*Message, error) {
	// Unmarshal JSONB content to ai.Part slice
	var content []*ai.Part
	if err := json.Unmarshal(sm.Content, &content); err != nil {
		return nil, fmt.Errorf("failed to unmarshal content: %w", err)
	}

	return &Message{
		ID:             pgUUIDToUUID(sm.ID),
		SessionID:      pgUUIDToUUID(sm.SessionID),
		Role:           sm.Role,
		Content:        content,
		SequenceNumber: int(sm.SequenceNumber),
		CreatedAt:      sm.CreatedAt.Time,
	}, nil
}

// uuidToPgUUID converts uuid.UUID to pgtype.UUID.
func uuidToPgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{
		Bytes: id,
		Valid: true,
	}
}

// pgUUIDToUUID converts pgtype.UUID to uuid.UUID.
func pgUUIDToUUID(pgUUID pgtype.UUID) uuid.UUID {
	if !pgUUID.Valid {
		return uuid.Nil
	}
	return pgUUID.Bytes
}
