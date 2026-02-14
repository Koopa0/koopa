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

	"github.com/koopa0/koopa/internal/config"
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

// CreateSession creates a new conversation session owned by the given user.
//
// Parameters:
//   - ctx: Context for the operation
//   - ownerID: User identity that owns this session
//   - title: Session title (empty string = no title)
//
// Returns:
//   - *Session: Created session with generated UUID
//   - error: If creation fails
func (s *Store) CreateSession(ctx context.Context, ownerID, title string) (*Session, error) {
	var titlePtr *string
	if title != "" {
		titlePtr = &title
	}

	sqlcSession, err := s.queries.CreateSession(ctx, sqlc.CreateSessionParams{
		Title:   titlePtr,
		OwnerID: ownerID,
	})
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	session := s.sqlcSessionToSession(sqlcSession)
	s.logger.Debug("created session", "id", session.ID, "owner", ownerID, "title", session.Title)
	return session, nil
}

// Session retrieves a session by ID.
// Returns ErrNotFound if the session does not exist.
func (s *Store) Session(ctx context.Context, sessionID uuid.UUID) (*Session, error) {
	row, err := s.queries.Session(ctx, sessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting session %s: %w", sessionID, err)
	}

	return s.sqlcSessionRowToSession(row), nil
}

// Sessions lists sessions owned by the given user, ordered by updated_at descending.
//
// Parameters:
//   - ctx: Context for the operation
//   - ownerID: User identity to filter by
//   - limit: Maximum number of sessions to return
//   - offset: Number of sessions to skip (for pagination)
//
// Returns:
//   - []*Session: List of sessions
//   - error: If listing fails
func (s *Store) Sessions(ctx context.Context, ownerID string, limit, offset int32) ([]*Session, error) {
	rows, err := s.queries.Sessions(ctx, sqlc.SessionsParams{
		OwnerID:      ownerID,
		ResultLimit:  limit,
		ResultOffset: offset,
	})
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}

	sessions := make([]*Session, 0, len(rows))
	for i := range rows {
		sessions = append(sessions, s.sqlcSessionsRowToSession(rows[i]))
	}

	s.logger.Debug("listed sessions", "owner", ownerID, "count", len(sessions), "limit", limit, "offset", offset)
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
		return fmt.Errorf("deleting session %s: %w", sessionID, err)
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
		return fmt.Errorf("updating session title %s: %w", sessionID, err)
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
		return fmt.Errorf("database pool is required for transactional operations")
	}

	// Begin transaction for atomicity
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
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
		return fmt.Errorf("locking session: %w", err)
	}

	// 1. Get current max sequence number within transaction
	maxSeq, err := txQuerier.MaxSequenceNumber(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("getting max sequence number: %w", err)
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
			return fmt.Errorf("marshaling message content at index %d: %w", i, marshalErr)
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
			return fmt.Errorf("inserting message %d: %w", i, err)
		}
	}

	// 3. Update session's updated_at within transaction
	if err = txQuerier.UpdateSessionUpdatedAt(ctx, sessionID); err != nil {
		// Transaction will be rolled back by defer
		return fmt.Errorf("updating session metadata: %w", err)
	}

	// 4. Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
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
		return nil, fmt.Errorf("getting messages for session %s: %w", sessionID, err)
	}

	messages := make([]*Message, 0, len(sqlcMessages))
	for i := range sqlcMessages {
		msg, err := s.sqlcMessageToMessage(sqlcMessages[i])
		if err != nil {
			s.logger.Warn("skipping malformed message",
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

// denormalizeRole converts database roles back to Genkit roles.
// Reverses normalizeRole: "assistant" → "model" so Gemini API accepts the history.
func denormalizeRole(role string) string {
	if role == "assistant" {
		return "model"
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
		return err // AddMessages already wraps with context
	}

	s.logger.Debug("appended messages",
		"session_id", sessionID,
		"count", len(messages))
	return nil
}

// History retrieves the conversation history for a session as a slice of ai.Message.
// Used by chat.Agent for session management.
func (s *Store) History(ctx context.Context, sessionID uuid.UUID) ([]*ai.Message, error) {
	// Verify session exists before loading history
	if _, err := s.Session(ctx, sessionID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, err // Sentinel propagates unchanged
		}
		return nil, fmt.Errorf("getting history for session %s: %w", sessionID, err)
	}

	// Retrieve messages
	messages, err := s.Messages(ctx, sessionID, config.DefaultMaxHistoryMessages, 0)
	if err != nil {
		return nil, fmt.Errorf("loading history: %w", err)
	}

	// Convert to ai.Message with reverse role normalization.
	// DB stores "assistant" but Gemini API requires "model".
	aiMessages := make([]*ai.Message, len(messages))
	for i, msg := range messages {
		aiMessages[i] = &ai.Message{
			Content: msg.Content,
			Role:    ai.Role(denormalizeRole(msg.Role)),
		}
	}

	s.logger.Debug("loaded history",
		"session_id", sessionID,
		"count", len(messages))

	return aiMessages, nil
}

// ResolveCurrentSession loads the active session from the state file,
// validates it exists in the database, and creates a new session if needed.
// Returns the session ID.
func (s *Store) ResolveCurrentSession(ctx context.Context) (uuid.UUID, error) {
	//nolint:contextcheck // LoadCurrentSessionID manages its own lock timeout context
	savedID, err := LoadCurrentSessionID()
	if err != nil {
		return uuid.Nil, fmt.Errorf("loading current session: %w", err)
	}

	if savedID != nil {
		if _, err = s.Session(ctx, *savedID); err == nil {
			return *savedID, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return uuid.Nil, fmt.Errorf("validating session: %w", err)
		}
	}

	newSess, err := s.CreateSession(ctx, "cli", "")
	if err != nil {
		return uuid.Nil, fmt.Errorf("creating session: %w", err)
	}

	// best-effort: state file is non-critical, session already created in DB
	//nolint:contextcheck // SaveCurrentSessionID manages its own lock timeout context
	if saveErr := SaveCurrentSessionID(newSess.ID); saveErr != nil {
		s.logger.Warn("saving session state", "error", saveErr)
	}

	return newSess.ID, nil
}

// sqlcSessionToSession converts sqlc.Session (from CreateSession RETURNING *) to Session.
func (*Store) sqlcSessionToSession(ss sqlc.Session) *Session {
	session := &Session{
		ID:        ss.ID,
		OwnerID:   ss.OwnerID,
		CreatedAt: ss.CreatedAt.Time,
		UpdatedAt: ss.UpdatedAt.Time,
	}
	if ss.Title != nil {
		session.Title = *ss.Title
	}
	return session
}

// sqlcSessionRowToSession converts sqlc.SessionRow (from Session query) to Session.
func (*Store) sqlcSessionRowToSession(row sqlc.SessionRow) *Session {
	session := &Session{
		ID:        row.ID,
		OwnerID:   row.OwnerID,
		CreatedAt: row.CreatedAt.Time,
		UpdatedAt: row.UpdatedAt.Time,
	}
	if row.Title != nil {
		session.Title = *row.Title
	}
	return session
}

// sqlcSessionsRowToSession converts sqlc.SessionsRow (from Sessions query) to Session.
func (*Store) sqlcSessionsRowToSession(row sqlc.SessionsRow) *Session {
	session := &Session{
		ID:        row.ID,
		OwnerID:   row.OwnerID,
		CreatedAt: row.CreatedAt.Time,
		UpdatedAt: row.UpdatedAt.Time,
	}
	if row.Title != nil {
		session.Title = *row.Title
	}
	return session
}

// sqlcMessageToMessage converts sqlc.Message to Message (application type).
func (*Store) sqlcMessageToMessage(sm sqlc.Message) (*Message, error) {
	// Unmarshal JSONB content to ai.Part slice
	var content []*ai.Part
	if err := json.Unmarshal(sm.Content, &content); err != nil {
		return nil, fmt.Errorf("unmarshaling content: %w", err)
	}

	return &Message{
		ID:             sm.ID,
		SessionID:      sm.SessionID,
		Role:           sm.Role,
		Content:        content,
		SequenceNumber: int(sm.SequenceNumber),
		CreatedAt:      sm.CreatedAt.Time,
	}, nil
}
