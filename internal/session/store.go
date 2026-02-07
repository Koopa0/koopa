package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/koopa/internal/sqlc"
)

// Store manages session persistence with PostgreSQL backend.
// It handles conversation history storage and retrieval.
//
// Store is safe for concurrent use by multiple goroutines.
type Store struct {
	queries *sqlc.Queries
	pool    *pgxpool.Pool // Database pool for transaction support
	logger  *slog.Logger
}

// New creates a new Store instance.
//
// Parameters:
//   - queries: sqlc generated queries
//   - pool: PostgreSQL connection pool (for transaction support)
//   - logger: Logger for debugging (nil = use default)
//
// Example:
//
//	store := session.New(sqlc.New(dbPool), dbPool, slog.Default())
func New(queries *sqlc.Queries, pool *pgxpool.Pool, logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}

	return &Store{
		queries: queries,
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

	sqlcSession, err := s.queries.CreateSession(ctx, sqlc.CreateSessionParams{
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

// Session retrieves a session by ID.
// Returns ErrSessionNotFound if the session does not exist.
func (s *Store) Session(ctx context.Context, sessionID uuid.UUID) (*Session, error) {
	sqlcSession, err := s.queries.Session(ctx, sessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Return sentinel error directly (no wrapping per reviewer guidance)
			return nil, ErrSessionNotFound
		}
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
	sqlcSessions, err := s.queries.ListSessions(ctx, sqlc.ListSessionsParams{
		ResultLimit:  limit,
		ResultOffset: offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	sessions := make([]*Session, 0, len(sqlcSessions))
	for i := range sqlcSessions {
		sessions = append(sessions, s.sqlcSessionToSession(sqlcSessions[i]))
	}

	s.logger.Debug("listed sessions", "count", len(sessions), "limit", limit, "offset", offset)
	return sessions, nil
}

// ListSessionsWithMessages lists sessions that have messages or titles.
// This is used for sidebar display where empty "New Chat" placeholder sessions should be hidden.
//
// Parameters:
//   - ctx: Context for the operation
//   - limit: Maximum number of sessions to return
//   - offset: Number of sessions to skip (for pagination)
//
// Returns:
//   - []*Session: List of sessions with messages or titles
//   - error: If listing fails
func (s *Store) ListSessionsWithMessages(ctx context.Context, limit, offset int32) ([]*Session, error) {
	sqlcSessions, err := s.queries.ListSessionsWithMessages(ctx, sqlc.ListSessionsWithMessagesParams{
		ResultLimit:  limit,
		ResultOffset: offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions with messages: %w", err)
	}

	sessions := make([]*Session, 0, len(sqlcSessions))
	for i := range sqlcSessions {
		sessions = append(sessions, s.sqlcSessionToSession(sqlcSessions[i]))
	}

	s.logger.Debug("listed sessions with messages", "count", len(sessions), "limit", limit, "offset", offset)
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
	if err := s.queries.DeleteSession(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to delete session %s: %w", sessionID, err)
	}

	s.logger.Debug("deleted session", "id", sessionID)
	return nil
}

// UpdateSessionTitle updates the display title for a session.
// Used for auto-generating titles from first message or user edits.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: UUID of the session to update
//   - title: New title (empty string clears the title)
//
// Returns:
//   - error: If update fails
func (s *Store) UpdateSessionTitle(ctx context.Context, sessionID uuid.UUID, title string) error {
	var titlePtr *string
	if title != "" {
		titlePtr = &title
	}

	if err := s.queries.UpdateSessionTitle(ctx, sqlc.UpdateSessionTitleParams{
		SessionID: sessionID,
		Title:     titlePtr,
	}); err != nil {
		return fmt.Errorf("failed to update session title %s: %w", sessionID, err)
	}

	s.logger.Debug("updated session title", "id", sessionID, "title", title)
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

	// Database pool is required for transactional operations
	// Tests should use pgxmock or Testcontainers for proper transaction testing
	if s.pool == nil {
		return fmt.Errorf("database pool required for AddMessages: use pgxmock or real database for testing")
	}

	// Begin transaction for atomicity
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	// Rollback if not committed - log any rollback errors for debugging
	defer func() {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			s.logger.Debug("transaction rollback (may be already committed)", "error", rollbackErr)
		}
	}()

	// Create querier for this transaction
	txQuerier := sqlc.New(tx)

	// 0. Lock session row to prevent concurrent modifications
	// This SELECT ... FOR UPDATE ensures that only one transaction can modify
	// this session at a time, preventing race conditions on sequence numbers
	if _, err = txQuerier.LockSession(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to lock session: %w", err)
	}

	// 1. Get current max sequence number within transaction
	maxSeq, err := txQuerier.GetMaxSequenceNumber(ctx, sessionID)
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
		contentJSON, marshalErr := json.Marshal(msg.Content)
		if marshalErr != nil {
			// Transaction will be rolled back by defer
			return fmt.Errorf("failed to marshal message content at index %d: %w", i, marshalErr)
		}

		// Calculate sequence number (maxSeq is now int32 from sqlc)
		// Safe conversion: loop index i is bounded by len(messages) which is checked by database constraints
		seqNum := maxSeq + int32(i) + 1 // #nosec G115 -- i is loop index bounded by slice length

		if err = txQuerier.AddMessage(ctx, sqlc.AddMessageParams{
			SessionID:      sessionID,
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
		SessionID:    sessionID,
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

// Messages retrieves messages for a session with pagination.
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
func (s *Store) Messages(ctx context.Context, sessionID uuid.UUID, limit, offset int32) ([]*Message, error) {
	sqlcMessages, err := s.queries.Messages(ctx, sqlc.MessagesParams{
		SessionID:    sessionID,
		ResultLimit:  limit,
		ResultOffset: offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get messages for session %s: %w", sessionID, err)
	}

	messages := make([]*Message, 0, len(sqlcMessages))
	for i := range sqlcMessages {
		msg, err := s.sqlcMessageToMessage(sqlcMessages[i])
		if err != nil {
			s.logger.Warn("failed to unmarshal message content",
				"message_id", sqlcMessages[i].ID,
				"error", err)
			continue // Skip malformed messages
		}
		messages = append(messages, msg)
	}

	s.logger.Debug("retrieved messages", "session_id", sessionID, "count", len(messages))
	return messages, nil
}

// normalizeRole converts Genkit roles to database-canonical roles.
// Genkit uses ai.RoleModel = "model" but we store "assistant" for consistency
// with the database CHECK constraint.
func normalizeRole(role string) string {
	if role == "model" {
		return "assistant"
	}
	return role
}

// AppendMessages appends new messages to a session.
// This is the preferred method for saving conversation history.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: Session UUID
//   - messages: Messages to append
//
// Returns:
//   - error: If saving fails
func (s *Store) AppendMessages(ctx context.Context, sessionID uuid.UUID, messages []*ai.Message) error {
	if len(messages) == 0 {
		return nil
	}

	// Convert ai.Message to session.Message with role normalization
	sessionMessages := make([]*Message, len(messages))
	for i, msg := range messages {
		sessionMessages[i] = &Message{
			Role:    normalizeRole(string(msg.Role)),
			Content: msg.Content,
		}
	}

	// Use AddMessages
	if err := s.AddMessages(ctx, sessionID, sessionMessages); err != nil {
		return fmt.Errorf("failed to append messages: %w", err)
	}

	s.logger.Debug("appended messages",
		"session_id", sessionID,
		"count", len(messages))
	return nil
}

// History retrieves the conversation history for a session.
// Used by chat.Chat agent for session management.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: Session UUID
//
// Returns:
//   - *History: Conversation history
//   - error: If retrieval fails
func (s *Store) History(ctx context.Context, sessionID uuid.UUID) (*History, error) {
	// Verify session exists before loading history
	if _, err := s.Session(ctx, sessionID); err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return nil, err // Sentinel propagates unchanged
		}
		return nil, fmt.Errorf("get history for session %s: %w", sessionID, err)
	}

	// Use default limit for history retrieval
	limit := DefaultHistoryLimit

	// Retrieve messages
	messages, err := s.Messages(ctx, sessionID, limit, 0)
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
		"message_count", len(messages))

	history := NewHistory()
	history.SetMessages(aiMessages)
	return history, nil
}

// sqlcSessionToSession converts sqlc.Session to Session (application type).
func (*Store) sqlcSessionToSession(ss sqlc.Session) *Session {
	session := &Session{
		ID:        ss.ID,
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

// sqlcMessageToMessage converts sqlc.Message to Message (application type).
func (*Store) sqlcMessageToMessage(sm sqlc.Message) (*Message, error) {
	// Unmarshal JSONB content to ai.Part slice
	var content []*ai.Part
	if err := json.Unmarshal(sm.Content, &content); err != nil {
		return nil, fmt.Errorf("failed to unmarshal content: %w", err)
	}

	return &Message{
		ID:             sm.ID,
		SessionID:      sm.SessionID,
		Role:           sm.Role,
		Content:        content,
		Status:         sm.Status,
		SequenceNumber: int(sm.SequenceNumber),
		CreatedAt:      sm.CreatedAt.Time,
	}, nil
}

// =============================================================================
// Streaming Message Operations (for SSE chat flow)
// =============================================================================

// MessagePair represents a user-assistant message pair created for streaming.
// Used to track both messages atomically for SSE-based chat.
type MessagePair struct {
	UserMsgID      uuid.UUID
	AssistantMsgID uuid.UUID
	UserSeq        int32
	AssistantSeq   int32
}

// CreateMessagePair atomically creates a user message and empty assistant placeholder.
// The user message is marked as "completed", the assistant message as "streaming".
// This is used at the start of a chat turn before SSE streaming begins.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: UUID of the session
//   - userContent: User message content as ai.Part slice
//   - assistantID: Pre-generated UUID for the assistant message (used in SSE URL)
//
// Returns:
//   - *MessagePair: Contains both message IDs and sequence numbers
//   - error: If creation fails or session doesn't exist
func (s *Store) CreateMessagePair(
	ctx context.Context,
	sessionID uuid.UUID,
	userContent []*ai.Part,
	assistantID uuid.UUID,
) (*MessagePair, error) {
	// Database pool is required for transactional operations
	if s.pool == nil {
		return nil, fmt.Errorf("database pool required for CreateMessagePair")
	}

	// Begin transaction for atomicity
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			s.logger.Debug("transaction rollback (may be already committed)", "error", rollbackErr)
		}
	}()

	txQuerier := sqlc.New(tx)

	// Lock session row to prevent concurrent modifications
	_, err = txQuerier.LockSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("lock session: %w", err)
	}

	// Get current max sequence number
	maxSeq, err := txQuerier.GetMaxSequenceNumber(ctx, sessionID)
	if err != nil {
		s.logger.Debug("no existing messages, starting from sequence 0",
			"session_id", sessionID)
		maxSeq = 0
	}

	// Marshal user content to JSON
	userContentJSON, err := json.Marshal(userContent)
	if err != nil {
		return nil, fmt.Errorf("marshal user content: %w", err)
	}

	// Generate user message ID
	userMsgID := uuid.New()
	userSeq := maxSeq + 1
	assistantSeq := maxSeq + 2

	// Insert user message (status = completed)
	_, err = txQuerier.AddMessageWithID(ctx, sqlc.AddMessageWithIDParams{
		ID:             userMsgID,
		SessionID:      sessionID,
		Role:           "user",
		Content:        userContentJSON,
		Status:         StatusCompleted,
		SequenceNumber: userSeq,
	})
	if err != nil {
		return nil, fmt.Errorf("insert user message: %w", err)
	}

	// Insert empty assistant message placeholder (status = streaming)
	emptyContent := []byte("[]") // Empty ai.Part slice
	_, err = txQuerier.AddMessageWithID(ctx, sqlc.AddMessageWithIDParams{
		ID:             assistantID,
		SessionID:      sessionID,
		Role:           RoleAssistant,
		Content:        emptyContent,
		Status:         StatusStreaming,
		SequenceNumber: assistantSeq,
	})
	if err != nil {
		return nil, fmt.Errorf("insert assistant message: %w", err)
	}

	// Update session metadata
	if err = txQuerier.UpdateSessionUpdatedAt(ctx, sqlc.UpdateSessionUpdatedAtParams{
		MessageCount: &assistantSeq,
		SessionID:    sessionID,
	}); err != nil {
		return nil, fmt.Errorf("update session metadata: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	s.logger.Debug("created message pair",
		"session_id", sessionID,
		"user_msg_id", userMsgID,
		"assistant_msg_id", assistantID)

	return &MessagePair{
		UserMsgID:      userMsgID,
		AssistantMsgID: assistantID,
		UserSeq:        userSeq,
		AssistantSeq:   assistantSeq,
	}, nil
}

// UpdateMessageContent updates the content of a message and marks it as completed.
// Used after streaming is finished to save the final AI response.
func (s *Store) UpdateMessageContent(ctx context.Context, msgID uuid.UUID, content []*ai.Part) error {
	contentJSON, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("marshal content: %w", err)
	}

	if err := s.queries.UpdateMessageContent(ctx, sqlc.UpdateMessageContentParams{
		ID:      msgID,
		Content: contentJSON,
	}); err != nil {
		return fmt.Errorf("update message content: %w", err)
	}

	s.logger.Debug("updated message content", "msg_id", msgID)
	return nil
}

// UpdateMessageStatus updates the status of a message.
// Used to mark streaming messages as failed if an error occurs.
func (s *Store) UpdateMessageStatus(ctx context.Context, msgID uuid.UUID, status string) error {
	if err := s.queries.UpdateMessageStatus(ctx, sqlc.UpdateMessageStatusParams{
		ID:     msgID,
		Status: status,
	}); err != nil {
		return fmt.Errorf("update message status: %w", err)
	}

	s.logger.Debug("updated message status", "msg_id", msgID, "status", status)
	return nil
}
