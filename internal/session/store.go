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

	"github.com/koopa0/koopa-cli/internal/sqlc"
)

// SessionQuerier defines the interface for database operations on sessions and messages.
// Following Go best practices: interfaces are defined by the consumer, not the provider.
//
// This interface allows Store to depend on abstraction rather than concrete implementation,
// improving testability and flexibility.
type SessionQuerier interface {
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
	GetMaxSequenceNumber(ctx context.Context, sessionID pgtype.UUID) (interface{}, error)
}

// Store manages session persistence with PostgreSQL backend.
// It handles conversation history storage and retrieval.
//
// Store is safe for concurrent use by multiple goroutines.
type Store struct {
	querier SessionQuerier // Depends on interface for testability
	pool    *pgxpool.Pool  // Database pool for transaction support
	logger  *slog.Logger
}

// New creates a new Store instance.
//
// Parameters:
//   - dbPool: PostgreSQL connection pool (pgxpool)
//   - logger: Logger for debugging (nil = use default)
//
// Example:
//
//	store := session.New(dbPool, slog.Default())
//
// Design: Accepts dbPool and converts to SessionQuerier interface internally.
// For testing, use NewWithQuerier to inject mock querier directly.
func New(dbPool *pgxpool.Pool, logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}
	return &Store{
		querier: sqlc.New(dbPool),
		pool:    dbPool,
		logger:  logger,
	}
}

// NewWithQuerier creates a new Store instance with custom querier (useful for testing).
//
// Parameters:
//   - querier: Database querier implementing SessionQuerier interface
//   - logger: Logger for debugging (nil = use default)
//
// Design: Accepts SessionQuerier interface following "Accept interfaces, return structs"
// principle for better testability.
func NewWithQuerier(querier SessionQuerier, logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}

	return &Store{
		querier: querier,
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
func (s *Store) ListSessions(ctx context.Context, limit, offset int) ([]*Session, error) {
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
	defer func() { _ = tx.Rollback(ctx) }() // Rollback if not committed

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
	maxSeqRaw, err := txQuerier.GetMaxSequenceNumber(ctx, uuidToPgUUID(sessionID))
	if err != nil {
		// If session doesn't exist yet or no messages, start from 0
		s.logger.Debug("no existing messages, starting from sequence 0",
			"session_id", sessionID)
		maxSeqRaw = int64(0)
	}

	// Convert interface{} to int64
	var maxSeq int64
	switch v := maxSeqRaw.(type) {
	case int64:
		maxSeq = v
	case int32:
		maxSeq = int64(v)
	case int:
		maxSeq = int64(v)
	default:
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

		seqNum := int32(maxSeq) + int32(i) + 1

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
	newCount := int32(maxSeq) + int32(len(messages))
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
	maxSeqRaw, err := s.querier.GetMaxSequenceNumber(ctx, uuidToPgUUID(sessionID))
	if err != nil {
		s.logger.Debug("no existing messages, starting from sequence 0",
			"session_id", sessionID)
		maxSeqRaw = int64(0)
	}

	// Convert interface{} to int64
	var maxSeq int64
	switch v := maxSeqRaw.(type) {
	case int64:
		maxSeq = v
	case int32:
		maxSeq = int64(v)
	case int:
		maxSeq = int64(v)
	default:
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

		seqNum := int32(maxSeq) + int32(i) + 1

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
	newCount := int32(maxSeq) + int32(len(messages))
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
func (s *Store) GetMessages(ctx context.Context, sessionID uuid.UUID, limit, offset int) ([]*Message, error) {
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
