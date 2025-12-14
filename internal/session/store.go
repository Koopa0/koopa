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
	ListSessionsWithMessages(ctx context.Context, arg sqlc.ListSessionsWithMessagesParams) ([]sqlc.Session, error)
	UpdateSessionUpdatedAt(ctx context.Context, arg sqlc.UpdateSessionUpdatedAtParams) error
	UpdateSessionTitle(ctx context.Context, arg sqlc.UpdateSessionTitleParams) error
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

	// Streaming message operations (for SSE chat flow)
	AddMessageWithID(ctx context.Context, arg sqlc.AddMessageWithIDParams) (sqlc.SessionMessage, error)
	UpdateMessageContent(ctx context.Context, arg sqlc.UpdateMessageContentParams) error
	UpdateMessageStatus(ctx context.Context, arg sqlc.UpdateMessageStatusParams) error
	GetMessageByID(ctx context.Context, id pgtype.UUID) (sqlc.SessionMessage, error)
	GetUserMessageBefore(ctx context.Context, arg sqlc.GetUserMessageBeforeParams) ([]byte, error)

	// Canvas mode and artifact operations
	UpdateCanvasMode(ctx context.Context, arg sqlc.UpdateCanvasModeParams) error
	CreateArtifact(ctx context.Context, arg sqlc.CreateArtifactParams) (sqlc.SessionArtifact, error)
	GetLatestArtifact(ctx context.Context, sessionID pgtype.UUID) (sqlc.SessionArtifact, error)
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
// Returns ErrSessionNotFound if the session does not exist.
func (s *Store) GetSession(ctx context.Context, sessionID uuid.UUID) (*Session, error) {
	sqlcSession, err := s.querier.GetSession(ctx, uuidToPgUUID(sessionID))
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
	sqlcSessions, err := s.querier.ListSessions(ctx, sqlc.ListSessionsParams{
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
	sqlcSessions, err := s.querier.ListSessionsWithMessages(ctx, sqlc.ListSessionsWithMessagesParams{
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
	if err := s.querier.DeleteSession(ctx, uuidToPgUUID(sessionID)); err != nil {
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

	if err := s.querier.UpdateSessionTitle(ctx, sqlc.UpdateSessionTitleParams{
		SessionID: uuidToPgUUID(sessionID),
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
	if _, err = txQuerier.LockSession(ctx, uuidToPgUUID(sessionID)); err != nil {
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
		contentJSON, marshalErr := json.Marshal(msg.Content)
		if marshalErr != nil {
			// Transaction will be rolled back by defer
			return fmt.Errorf("failed to marshal message content at index %d: %w", i, marshalErr)
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
	for i := range sqlcMessages {
		msg, err := s.sqlcMessageToMessage(sqlcMessages[i])
		if err != nil {
			s.logger.Warn("failed to unmarshal message content",
				"message_id", pgUUIDToUUID(sqlcMessages[i].ID),
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
	for i := range sqlcMessages {
		msg, err := s.sqlcMessageToMessage(sqlcMessages[i])
		if err != nil {
			s.logger.Warn("failed to unmarshal message content",
				"message_id", pgUUIDToUUID(sqlcMessages[i].ID),
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
	branch, err = NormalizeBranch(branch)
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

	// Database pool is required for transactional operations
	if s.pool == nil {
		return fmt.Errorf("database pool required for AddMessagesWithBranch: use pgxmock or real database for testing")
	}

	// Begin transaction for atomicity
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			s.logger.Debug("transaction rollback (may be already committed)", "error", rollbackErr)
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

		contentJSON, marshalErr := json.Marshal(msg.Content)
		if marshalErr != nil {
			return fmt.Errorf("failed to marshal message content at index %d: %w", i, marshalErr)
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
	branch, err = NormalizeBranch(branch)
	if err != nil {
		return nil, fmt.Errorf("invalid branch: %w", err)
	}

	// Use default limit for history retrieval
	limit := DefaultHistoryLimit

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
//
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
	branch, err = NormalizeBranch(branch)
	if err != nil {
		return fmt.Errorf("invalid branch: %w", err)
	}

	// Get current messages from history
	aiMessages := history.Messages()
	if len(aiMessages) == 0 {
		return nil
	}

	// Load existing messages for this branch to determine which are new
	limit := DefaultHistoryLimit
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
func (*Store) sqlcSessionToSession(ss sqlc.Session) *Session {
	session := &Session{
		ID:         pgUUIDToUUID(ss.ID),
		CreatedAt:  ss.CreatedAt.Time,
		UpdatedAt:  ss.UpdatedAt.Time,
		CanvasMode: ss.CanvasMode,
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
func (*Store) sqlcMessageToMessage(sm sqlc.SessionMessage) (*Message, error) {
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
		Branch:         sm.Branch,
		Status:         sm.Status,
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
//   - branch: Branch name (empty defaults to "main")
//   - userContent: User message content as ai.Part slice
//   - assistantID: Pre-generated UUID for the assistant message (used in SSE URL)
//
// Returns:
//   - *MessagePair: Contains both message IDs and sequence numbers
//   - error: If creation fails or session doesn't exist
func (s *Store) CreateMessagePair(
	ctx context.Context,
	sessionID uuid.UUID,
	branch string,
	userContent []*ai.Part,
	assistantID uuid.UUID,
) (*MessagePair, error) {
	// Validate and normalize branch
	branch, err := NormalizeBranch(branch)
	if err != nil {
		return nil, fmt.Errorf("invalid branch: %w", err)
	}

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
	_, err = txQuerier.LockSession(ctx, uuidToPgUUID(sessionID))
	if err != nil {
		return nil, fmt.Errorf("lock session: %w", err)
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
		ID:             uuidToPgUUID(userMsgID),
		SessionID:      uuidToPgUUID(sessionID),
		Role:           "user",
		Content:        userContentJSON,
		Status:         StatusCompleted,
		Branch:         branch,
		SequenceNumber: userSeq,
	})
	if err != nil {
		return nil, fmt.Errorf("insert user message: %w", err)
	}

	// Insert empty assistant message placeholder (status = streaming)
	emptyContent := []byte("[]") // Empty ai.Part slice
	_, err = txQuerier.AddMessageWithID(ctx, sqlc.AddMessageWithIDParams{
		ID:             uuidToPgUUID(assistantID),
		SessionID:      uuidToPgUUID(sessionID),
		Role:           "assistant",
		Content:        emptyContent,
		Status:         StatusStreaming,
		Branch:         branch,
		SequenceNumber: assistantSeq,
	})
	if err != nil {
		return nil, fmt.Errorf("insert assistant message: %w", err)
	}

	// Update session metadata
	if err = txQuerier.UpdateSessionUpdatedAt(ctx, sqlc.UpdateSessionUpdatedAtParams{
		MessageCount: &assistantSeq,
		SessionID:    uuidToPgUUID(sessionID),
	}); err != nil {
		return nil, fmt.Errorf("update session metadata: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	s.logger.Debug("created message pair",
		"session_id", sessionID,
		"branch", branch,
		"user_msg_id", userMsgID,
		"assistant_msg_id", assistantID)

	return &MessagePair{
		UserMsgID:      userMsgID,
		AssistantMsgID: assistantID,
		UserSeq:        userSeq,
		AssistantSeq:   assistantSeq,
	}, nil
}

// GetUserMessageBefore retrieves the text content of the user message
// immediately preceding the specified sequence number.
// This is used by Stream handler to retrieve query without URL parameter.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: UUID of the session
//   - branch: Branch name (empty defaults to "main")
//   - beforeSeq: Sequence number to search before
//
// Returns:
//   - string: The user message text
//   - error: ErrMessageNotFound if no preceding user message exists
func (s *Store) GetUserMessageBefore(
	ctx context.Context,
	sessionID uuid.UUID,
	branch string,
	beforeSeq int32,
) (string, error) {
	// Validate and normalize branch
	branch, err := NormalizeBranch(branch)
	if err != nil {
		return "", fmt.Errorf("invalid branch: %w", err)
	}

	content, err := s.querier.GetUserMessageBefore(ctx, sqlc.GetUserMessageBeforeParams{
		SessionID:      uuidToPgUUID(sessionID),
		Branch:         branch,
		BeforeSequence: beforeSeq,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrMessageNotFound
		}
		return "", fmt.Errorf("get user message before %d: %w", beforeSeq, err)
	}

	// Unmarshal content to extract text
	var parts []*ai.Part
	if err := json.Unmarshal(content, &parts); err != nil {
		return "", fmt.Errorf("unmarshal content: %w", err)
	}

	// Extract text from parts
	var text string
	for _, p := range parts {
		if p != nil && (p.Kind == ai.PartText || p.Kind == ai.PartMedia) {
			text += p.Text
		}
	}

	if text == "" {
		return "", ErrMessageNotFound
	}

	return text, nil
}

// GetMessageByID retrieves a message by its ID.
// Used to get assistant message sequence number for user query lookup.
//
// Returns:
//   - *Message: The message if found
//   - error: ErrMessageNotFound if not found
func (s *Store) GetMessageByID(ctx context.Context, msgID uuid.UUID) (*Message, error) {
	sm, err := s.querier.GetMessageByID(ctx, uuidToPgUUID(msgID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrMessageNotFound
		}
		return nil, fmt.Errorf("get message %s: %w", msgID, err)
	}

	return s.sqlcMessageToMessage(sm)
}

// UpdateMessageContent updates the content of a message and marks it as completed.
// Used after streaming is finished to save the final AI response.
func (s *Store) UpdateMessageContent(ctx context.Context, msgID uuid.UUID, content []*ai.Part) error {
	contentJSON, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("marshal content: %w", err)
	}

	if err := s.querier.UpdateMessageContent(ctx, sqlc.UpdateMessageContentParams{
		ID:      uuidToPgUUID(msgID),
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
	if err := s.querier.UpdateMessageStatus(ctx, sqlc.UpdateMessageStatusParams{
		ID:     uuidToPgUUID(msgID),
		Status: status,
	}); err != nil {
		return fmt.Errorf("update message status: %w", err)
	}

	s.logger.Debug("updated message status", "msg_id", msgID, "status", status)
	return nil
}

// =============================================================================
// Canvas Mode and Artifact Operations
// =============================================================================

// UpdateCanvasMode toggles canvas mode for a session.
// Per golang-master: Error wrapping with context.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: UUID of the session
//   - canvasMode: New canvas mode state
//
// Returns:
//   - error: If update fails
func (s *Store) UpdateCanvasMode(ctx context.Context, sessionID uuid.UUID, canvasMode bool) error {
	if err := s.querier.UpdateCanvasMode(ctx, sqlc.UpdateCanvasModeParams{
		SessionID:  uuidToPgUUID(sessionID),
		CanvasMode: canvasMode,
	}); err != nil {
		return fmt.Errorf("update canvas mode for session %s: %w", sessionID, err)
	}

	s.logger.Debug("updated canvas mode", "session_id", sessionID, "canvas_mode", canvasMode)
	return nil
}

// SaveArtifact creates a new artifact for canvas panel (autosave).
// Per golang-master: Error wrapping with context.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: UUID of the session
//   - messageID: Optional message ID (nil if not linked to a message)
//   - artifact: Artifact data to save
//
// Returns:
//   - *Artifact: Created artifact with generated ID and sequence number
//   - error: If creation fails
func (s *Store) SaveArtifact(ctx context.Context, sessionID uuid.UUID, messageID *uuid.UUID, artifact *Artifact) (*Artifact, error) {
	var msgID pgtype.UUID
	if messageID != nil {
		msgID = uuidToPgUUID(*messageID)
	}

	// Convert language to nullable
	var language *string
	if artifact.Language != "" {
		language = &artifact.Language
	}

	result, err := s.querier.CreateArtifact(ctx, sqlc.CreateArtifactParams{
		SessionID: uuidToPgUUID(sessionID),
		MessageID: msgID,
		Type:      artifact.Type,
		Language:  language,
		Title:     artifact.Title,
		Content:   artifact.Content,
	})
	if err != nil {
		return nil, fmt.Errorf("create artifact for session %s: %w", sessionID, err)
	}

	saved := s.sqlcArtifactToArtifact(result)
	s.logger.Debug("saved artifact", "session_id", sessionID, "artifact_id", saved.ID, "type", saved.Type)
	return saved, nil
}

// GetLatestArtifact retrieves the most recent artifact for a session.
// Returns (nil, nil) if no artifacts exist for the session.
// Returns (nil, error) if a database error occurs.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionID: UUID of the session
//
// Returns:
//   - *Artifact: The latest artifact, or nil if none exists
//   - error: If a database error occurs (not for "not found")
func (s *Store) GetLatestArtifact(ctx context.Context, sessionID uuid.UUID) (*Artifact, error) {
	result, err := s.querier.GetLatestArtifact(ctx, uuidToPgUUID(sessionID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrArtifactNotFound // Normal state for new sessions without canvas output
		}
		return nil, fmt.Errorf("get latest artifact for session %s: %w", sessionID, err)
	}

	return s.sqlcArtifactToArtifact(result), nil
}

// sqlcArtifactToArtifact converts sqlc.SessionArtifact to Artifact (application type).
func (*Store) sqlcArtifactToArtifact(sa sqlc.SessionArtifact) *Artifact {
	artifact := &Artifact{
		ID:             pgUUIDToUUID(sa.ID),
		SessionID:      pgUUIDToUUID(sa.SessionID),
		Type:           sa.Type,
		Title:          sa.Title,
		Content:        sa.Content,
		Version:        int(sa.Version),
		SequenceNumber: int(sa.SequenceNumber),
		CreatedAt:      sa.CreatedAt.Time,
		UpdatedAt:      sa.UpdatedAt.Time,
	}

	// Handle nullable fields
	if sa.MessageID.Valid {
		msgID := pgUUIDToUUID(sa.MessageID)
		artifact.MessageID = &msgID
	}
	if sa.Language != nil {
		artifact.Language = *sa.Language
	}

	return artifact
}
