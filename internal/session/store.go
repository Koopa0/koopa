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
	"github.com/koopa0/koopa-cli/internal/config"
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
	LockSession(ctx context.Context, id pgtype.UUID) (pgtype.UUID, error)

	// Message operations (legacy - defaults to 'main' branch)
	AddMessage(ctx context.Context, arg sqlc.AddMessageParams) error
	GetMessages(ctx context.Context, arg sqlc.GetMessagesParams) ([]sqlc.SessionMessage, error)
	GetMaxSequenceNumber(ctx context.Context, sessionID pgtype.UUID) (int32, error)

	// Message operations with branch support
	AddMessageWithBranch(ctx context.Context, arg sqlc.AddMessageWithBranchParams) error
	GetMessagesByBranch(ctx context.Context, arg sqlc.GetMessagesByBranchParams) ([]sqlc.SessionMessage, error)
	GetMaxSequenceByBranch(ctx context.Context, arg sqlc.GetMaxSequenceByBranchParams) (int32, error)
	CountMessagesByBranch(ctx context.Context, arg sqlc.CountMessagesByBranchParams) (int32, error)
	DeleteMessagesByBranch(ctx context.Context, arg sqlc.DeleteMessagesByBranchParams) error
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

	// 0. Lock session row to prevent concurrent modifications
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
		// Validate Content slice for nil pointers
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
		// Validate Content slice for nil pointers
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

// GetMessagesByBranch retrieves messages for a session filtered by branch.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: UUID of the session
//   - branch: Branch name to filter by
//   - limit: Maximum number of messages to return
//   - offset: Number of messages to skip (for pagination)
//
// Returns:
//   - []*Message: List of messages ordered by sequence number ascending
//   - error: If retrieval fails
func (s *Store) GetMessagesByBranch(ctx context.Context, sessionID uuid.UUID, branch string, limit, offset int32) ([]*Message, error) {
	sqlcMessages, err := s.querier.GetMessagesByBranch(ctx, sqlc.GetMessagesByBranchParams{
		SessionID:    uuidToPgUUID(sessionID),
		Branch:       branch,
		ResultLimit:  limit,
		ResultOffset: offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get messages for session %s branch %s: %w", sessionID, branch, err)
	}

	messages := make([]*Message, 0, len(sqlcMessages))
	for _, sm := range sqlcMessages {
		msg, err := s.sqlcMessageToMessage(sm)
		if err != nil {
			s.logger.Warn("failed to unmarshal message content",
				"message_id", pgUUIDToUUID(sm.ID),
				"error", err)
			continue
		}
		messages = append(messages, msg)
	}

	s.logger.Debug("retrieved messages by branch",
		"session_id", sessionID,
		"branch", branch,
		"count", len(messages))
	return messages, nil
}

// AppendMessages appends new messages to a session branch.
// This is the preferred method for saving conversation history.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: agent.SessionID (UUID string)
//   - branch: Branch name (empty defaults to "main")
//   - messages: Messages to append
//
// Returns:
//   - error: If saving fails or branch is invalid
func (s *Store) AppendMessages(ctx context.Context, sessionID agent.SessionID, branch string, messages []*ai.Message) error {
	if len(messages) == 0 {
		return nil
	}

	// Parse SessionID to UUID
	id, err := uuid.Parse(string(sessionID))
	if err != nil {
		return fmt.Errorf("invalid session ID: %w", err)
	}

	// Validate and normalize branch
	branch, err = config.NormalizeBranch(branch)
	if err != nil {
		return fmt.Errorf("invalid branch: %w", err)
	}

	// Convert ai.Message to session.Message
	sessionMessages := make([]*Message, len(messages))
	for i, msg := range messages {
		sessionMessages[i] = &Message{
			Role:    string(msg.Role),
			Content: msg.Content,
		}
	}

	// Use branch-aware AddMessages
	if err := s.AddMessagesWithBranch(ctx, id, branch, sessionMessages); err != nil {
		return fmt.Errorf("failed to append messages: %w", err)
	}

	s.logger.Debug("appended messages",
		"session_id", sessionID,
		"branch", branch,
		"count", len(messages))
	return nil
}

// AddMessagesWithBranch adds multiple messages to a session branch in batch.
// This is more efficient than adding messages one by one.
//
// All operations are wrapped in a database transaction to ensure atomicity.
func (s *Store) AddMessagesWithBranch(ctx context.Context, sessionID uuid.UUID, branch string, messages []*Message) error {
	if len(messages) == 0 {
		return nil
	}

	// If pool is nil (testing with mock), use non-transactional mode
	if s.pool == nil {
		return s.addMessagesWithBranchNonTransactional(ctx, sessionID, branch, messages)
	}

	// Begin transaction for atomicity
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil {
			s.logger.Debug("transaction rollback (may be already committed)", "error", err)
		}
	}()

	txQuerier := sqlc.New(tx)

	// Lock session row to prevent concurrent modifications
	_, err = txQuerier.LockSession(ctx, uuidToPgUUID(sessionID))
	if err != nil {
		return fmt.Errorf("failed to lock session: %w", err)
	}

	// Get current max sequence number for this branch
	maxSeq, err := txQuerier.GetMaxSequenceByBranch(ctx, sqlc.GetMaxSequenceByBranchParams{
		SessionID: uuidToPgUUID(sessionID),
		Branch:    branch,
	})
	if err != nil {
		s.logger.Debug("no existing messages in branch, starting from sequence 0",
			"session_id", sessionID, "branch", branch)
		maxSeq = 0
	}

	// Insert messages
	for i, msg := range messages {
		for j, part := range msg.Content {
			if part == nil {
				return fmt.Errorf("message %d has nil content at index %d", i, j)
			}
		}

		contentJSON, err := json.Marshal(msg.Content)
		if err != nil {
			return fmt.Errorf("failed to marshal message content at index %d: %w", i, err)
		}

		seqNum := maxSeq + int32(i) + 1 // #nosec G115 -- i is loop index bounded by slice length

		if err = txQuerier.AddMessageWithBranch(ctx, sqlc.AddMessageWithBranchParams{
			SessionID:      uuidToPgUUID(sessionID),
			Branch:         branch,
			Role:           msg.Role,
			Content:        contentJSON,
			SequenceNumber: seqNum,
		}); err != nil {
			return fmt.Errorf("failed to insert message %d: %w", i, err)
		}
	}

	// Update session metadata
	newCount := maxSeq + int32(len(messages)) // #nosec G115 -- len bounded by practical message limits
	if err = txQuerier.UpdateSessionUpdatedAt(ctx, sqlc.UpdateSessionUpdatedAtParams{
		MessageCount: &newCount,
		SessionID:    uuidToPgUUID(sessionID),
	}); err != nil {
		return fmt.Errorf("failed to update session metadata: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	s.logger.Debug("added messages with branch",
		"session_id", sessionID,
		"branch", branch,
		"count", len(messages))
	return nil
}

// addMessagesWithBranchNonTransactional adds messages without transaction (for testing).
func (s *Store) addMessagesWithBranchNonTransactional(ctx context.Context, sessionID uuid.UUID, branch string, messages []*Message) error {
	maxSeq, err := s.querier.GetMaxSequenceByBranch(ctx, sqlc.GetMaxSequenceByBranchParams{
		SessionID: uuidToPgUUID(sessionID),
		Branch:    branch,
	})
	if err != nil {
		s.logger.Debug("no existing messages in branch, starting from sequence 0",
			"session_id", sessionID, "branch", branch)
		maxSeq = 0
	}

	for i, msg := range messages {
		for j, part := range msg.Content {
			if part == nil {
				return fmt.Errorf("message %d has nil content at index %d", i, j)
			}
		}

		contentJSON, err := json.Marshal(msg.Content)
		if err != nil {
			return fmt.Errorf("failed to marshal message content at index %d: %w", i, err)
		}

		seqNum := maxSeq + int32(i) + 1 // #nosec G115 -- i is loop index bounded by slice length

		if err = s.querier.AddMessageWithBranch(ctx, sqlc.AddMessageWithBranchParams{
			SessionID:      uuidToPgUUID(sessionID),
			Branch:         branch,
			Role:           msg.Role,
			Content:        contentJSON,
			SequenceNumber: seqNum,
		}); err != nil {
			return fmt.Errorf("failed to insert message %d: %w", i, err)
		}
	}

	newCount := maxSeq + int32(len(messages)) // #nosec G115 -- len bounded by practical message limits
	if err = s.querier.UpdateSessionUpdatedAt(ctx, sqlc.UpdateSessionUpdatedAtParams{
		MessageCount: &newCount,
		SessionID:    uuidToPgUUID(sessionID),
	}); err != nil {
		return fmt.Errorf("failed to update session metadata: %w", err)
	}

	s.logger.Debug("added messages with branch (non-transactional)",
		"session_id", sessionID,
		"branch", branch,
		"count", len(messages))
	return nil
}

// LoadHistory retrieves the conversation history for a session and branch.
// Used by chat.Chat agent for session management.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: agent.SessionID (UUID string)
//   - branch: Branch name (empty defaults to "main")
//
// Returns:
//   - *agent.History: Conversation history for the specified branch
//   - error: If retrieval fails or branch is invalid
func (s *Store) LoadHistory(ctx context.Context, sessionID agent.SessionID, branch string) (*agent.History, error) {
	// Parse SessionID to UUID
	id, err := uuid.Parse(string(sessionID))
	if err != nil {
		return nil, fmt.Errorf("invalid session ID: %w", err)
	}

	// Verify session exists before loading history
	if _, err = s.GetSession(ctx, id); err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	// Validate and normalize branch
	branch, err = config.NormalizeBranch(branch)
	if err != nil {
		return nil, fmt.Errorf("invalid branch: %w", err)
	}

	// Use configurable limit
	limit := config.NormalizeMaxHistoryMessages(0) // Use default

	// Retrieve messages for this specific branch
	messages, err := s.GetMessagesByBranch(ctx, id, branch, limit, 0)
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

	s.logger.Debug("loaded history",
		"session_id", sessionID,
		"branch", branch,
		"message_count", len(messages))

	return agent.NewHistoryFromMessages(aiMessages), nil
}

// SaveHistory saves the conversation history for a session.
// Deprecated: Use AppendMessages instead for incremental updates.
// This method has poor performance as it loads all existing messages to determine new ones.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: agent.SessionID (UUID string)
//   - branch: Branch name (empty defaults to "main")
//   - history: Conversation history
//
// Returns:
//   - error: If saving fails
func (s *Store) SaveHistory(ctx context.Context, sessionID agent.SessionID, branch string, history *agent.History) error {
	// Parse SessionID to UUID
	id, err := uuid.Parse(string(sessionID))
	if err != nil {
		return fmt.Errorf("invalid session ID: %w", err)
	}

	// Validate and normalize branch
	branch, err = config.NormalizeBranch(branch)
	if err != nil {
		return fmt.Errorf("invalid branch: %w", err)
	}

	// Get current messages from history
	aiMessages := history.Messages()
	if len(aiMessages) == 0 {
		return nil
	}

	// Load existing messages for this branch to determine which are new
	limit := config.NormalizeMaxHistoryMessages(0)
	existingMessages, err := s.GetMessagesByBranch(ctx, id, branch, limit, 0)
	if err != nil {
		s.logger.Debug("no existing messages found", "session_id", sessionID, "branch", branch)
		existingMessages = nil
	}

	// Only save messages that don't already exist (compare by count)
	existingCount := len(existingMessages)
	if len(aiMessages) <= existingCount {
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

	// Add new messages with branch support
	if len(newMessages) > 0 {
		if err := s.AddMessagesWithBranch(ctx, id, branch, newMessages); err != nil {
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
