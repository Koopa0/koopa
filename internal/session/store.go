package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

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

	return s.sqlcSessionToSession(row), nil
}

// Sessions lists sessions owned by the given user, ordered by updated_at descending.
// Returns the sessions and total count for pagination.
//
// NOTE: When offset >= total matching sessions, returns (nil, 0, nil).
// The zero total indicates no rows were scanned, not that zero sessions exist.
func (s *Store) Sessions(ctx context.Context, ownerID string, limit, offset int) ([]*Session, int, error) {
	if s.pool == nil {
		return nil, 0, fmt.Errorf("database pool is required for listing sessions")
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	if offset > 10000 {
		offset = 10000
	}

	const listSQL = `
		SELECT s.id, s.title, s.owner_id, s.created_at, s.updated_at,
		       COALESCE(mc.cnt, 0) AS message_count,
		       COUNT(*) OVER() AS total
		FROM sessions s
		LEFT JOIN (
		    SELECT session_id, COUNT(*) AS cnt
		    FROM messages GROUP BY session_id
		) mc ON mc.session_id = s.id
		WHERE s.owner_id = $1
		ORDER BY s.updated_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := s.pool.Query(ctx, listSQL, ownerID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("listing sessions: %w", err)
	}
	defer rows.Close()

	sessions := make([]*Session, 0)
	var total int
	for rows.Next() {
		var ss Session
		var title *string
		if err := rows.Scan(&ss.ID, &title, &ss.OwnerID, &ss.CreatedAt, &ss.UpdatedAt, &ss.MessageCount, &total); err != nil {
			return nil, 0, fmt.Errorf("scanning session: %w", err)
		}
		if title != nil {
			ss.Title = *title
		}
		sessions = append(sessions, &ss)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterating sessions: %w", err)
	}

	return sessions, total, nil
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
	// Rollback if not committed — pgx.ErrTxClosed is expected after successful commit.
	defer func() {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			s.logger.Debug("transaction rollback", "error", rollbackErr)
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

		// Extract text content for FTS indexing.
		textContent := extractTextContent(msg.Content)
		var textContentPtr *string
		if textContent != "" {
			textContentPtr = &textContent
		}

		if err = txQuerier.AddMessage(ctx, sqlc.AddMessageParams{
			SessionID:      sessionID,
			Role:           msg.Role,
			Content:        contentJSON,
			SequenceNumber: seqNum,
			TextContent:    textContentPtr,
		}); err != nil {
			// Transaction will be rolled back by defer
			return fmt.Errorf("inserting message %d: %w", i, err)
		}
	}

	// 3. Update session's updated_at within transaction
	rows, updateErr := txQuerier.UpdateSessionUpdatedAt(ctx, sessionID)
	if updateErr != nil {
		return fmt.Errorf("updating session metadata: %w", updateErr)
	}
	if rows == 0 {
		return ErrNotFound // session disappeared between lock and update
	}

	// 4. Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	s.logger.Debug("added messages", "session_id", sessionID, "count", len(messages))
	return nil
}

// Messages retrieves messages for a session with pagination.
// Returns messages ordered by sequence number ascending and the total count.
//
// The offset cap is 100,000 (vs 10,000 for sessions/memories) because a single
// long-running session can accumulate far more messages than a user has sessions.
//
// NOTE: When offset >= total messages, returns (nil, 0, nil).
// The zero total indicates no rows were scanned, not that zero messages exist.
func (s *Store) Messages(ctx context.Context, sessionID uuid.UUID, limit, offset int) ([]*Message, int, error) {
	if s.pool == nil {
		return nil, 0, fmt.Errorf("database pool is required for listing messages")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	if offset > 100000 {
		offset = 100000
	}

	const messagesSQL = `
		SELECT id, session_id, role, content, sequence_number, created_at,
		       COUNT(*) OVER() AS total
		FROM messages
		WHERE session_id = $1
		ORDER BY sequence_number ASC
		LIMIT $2 OFFSET $3
	`

	rows, err := s.pool.Query(ctx, messagesSQL, sessionID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("getting messages for session %s: %w", sessionID, err)
	}
	defer rows.Close()

	var messages []*Message
	var total int
	for rows.Next() {
		var (
			id        uuid.UUID
			sid       uuid.UUID
			role      string
			content   []byte
			seqNum    int32
			createdAt time.Time
		)
		if err := rows.Scan(&id, &sid, &role, &content, &seqNum, &createdAt, &total); err != nil {
			return nil, 0, fmt.Errorf("scanning message: %w", err)
		}

		var parts []*ai.Part
		if err := json.Unmarshal(content, &parts); err != nil {
			s.logger.Warn("skipping malformed message", "message_id", id, "error", err)
			continue
		}

		messages = append(messages, &Message{
			ID:             id,
			SessionID:      sid,
			Role:           role,
			Content:        parts,
			SequenceNumber: int(seqNum),
			CreatedAt:      createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterating messages: %w", err)
	}

	return messages, total, nil
}

// Export retrieves a session and all its messages for export.
// Returns ErrNotFound if the session does not exist.
func (s *Store) Export(ctx context.Context, sessionID uuid.UUID) (*ExportData, error) {
	sess, err := s.Session(ctx, sessionID)
	if err != nil {
		return nil, err // ErrNotFound propagates unchanged
	}

	// Export loads all messages up to MaxAllowedHistoryMessages (10000).
	// The export endpoint is rate-limited and ownership-checked, so the
	// cap is sufficient to prevent OOM without needing pagination.
	msgs, _, err := s.Messages(ctx, sessionID, int(config.MaxAllowedHistoryMessages), 0)
	if err != nil {
		return nil, fmt.Errorf("exporting messages for session %s: %w", sessionID, err)
	}

	return &ExportData{Session: sess, Messages: msgs}, nil
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
	messages, _, err := s.Messages(ctx, sessionID, int(config.DefaultMaxHistoryMessages), 0)
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
	savedID, err := LoadCurrentSessionID("")
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
	if saveErr := SaveCurrentSessionID("", newSess.ID); saveErr != nil {
		s.logger.Warn("saving session state", "error", saveErr)
	}

	return newSess.ID, nil
}

// extractTextContent concatenates all text parts from an ai.Part slice.
// Used to populate the text_content column for full-text search indexing.
func extractTextContent(parts []*ai.Part) string {
	var b strings.Builder
	for _, p := range parts {
		if p != nil && p.Text != "" {
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

// SearchMessages performs full-text search across all messages owned by ownerID.
// Uses dual search strategy: tsvector first (English ranked), then trigram ILIKE
// fallback for CJK and other non-stemmed text if tsvector yields no results.
//
// NOTE: When offset >= total matching results, returns (nil, 0, nil).
// The zero total indicates no rows were scanned, not that zero messages match.
func (s *Store) SearchMessages(ctx context.Context, ownerID, query string, limit, offset int) ([]SearchResult, int, error) {
	if query == "" {
		return nil, 0, nil
	}
	if s.pool == nil {
		return nil, 0, fmt.Errorf("database pool is required for search")
	}
	// Reject null bytes to prevent query poisoning.
	if strings.ContainsRune(query, 0) {
		return nil, 0, nil
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	if offset > 10000 {
		offset = 10000
	}

	// Primary: tsvector ranked search (works well for English / stemmed text).
	results, total, err := s.searchMessagesTSVector(ctx, ownerID, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	// Fallback: trigram ILIKE search for CJK / non-stemmed text.
	// Only fires on the first page (offset=0) when tsvector yields nothing.
	if len(results) == 0 && offset == 0 {
		results, total, err = s.searchMessagesTrigram(ctx, ownerID, query, limit)
		if err != nil {
			return nil, 0, err
		}
	}

	return results, total, nil
}

// searchMessagesTSVector performs tsvector-based full-text search.
func (s *Store) searchMessagesTSVector(ctx context.Context, ownerID, query string, limit, offset int) ([]SearchResult, int, error) {
	const searchSQL = `
		SELECT m.id AS message_id, m.session_id, m.role, m.created_at,
		       COALESCE(s.title, '') AS session_title,
		       LEFT(COALESCE(m.text_content, ''), 200) AS snippet,
		       ts_rank_cd(m.search_text, plainto_tsquery('english', $2), 1) AS rank,
		       COUNT(*) OVER() AS total
		FROM messages m
		JOIN sessions s ON s.id = m.session_id
		WHERE s.owner_id = $1
		  AND m.search_text @@ plainto_tsquery('english', $2)
		ORDER BY rank DESC, m.created_at DESC
		LIMIT $3 OFFSET $4
	`

	rows, err := s.pool.Query(ctx, searchSQL, ownerID, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("searching messages (tsvector): %w", err)
	}
	defer rows.Close()

	return scanSearchResults(rows)
}

// searchMessagesTrigram performs trigram ILIKE fallback search for CJK text.
// Always starts at offset 0 (only called as fallback on first page).
func (s *Store) searchMessagesTrigram(ctx context.Context, ownerID, query string, limit int) ([]SearchResult, int, error) {
	const trigramSQL = `
		SELECT m.id AS message_id, m.session_id, m.role, m.created_at,
		       COALESCE(s.title, '') AS session_title,
		       LEFT(COALESCE(m.text_content, ''), 200) AS snippet,
		       similarity(m.text_content, $2) AS rank,
		       COUNT(*) OVER() AS total
		FROM messages m
		JOIN sessions s ON s.id = m.session_id
		WHERE s.owner_id = $1
		  AND m.text_content ILIKE '%' || $2 || '%'
		ORDER BY rank DESC, m.created_at DESC
		LIMIT $3
	`

	escaped := escapeLike(query)
	rows, err := s.pool.Query(ctx, trigramSQL, ownerID, escaped, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("searching messages (trigram): %w", err)
	}
	defer rows.Close()

	return scanSearchResults(rows)
}

// scanSearchResults reads SearchResult rows from a query that returns
// (message_id, session_id, role, created_at, session_title, snippet, rank, total).
func scanSearchResults(rows pgx.Rows) ([]SearchResult, int, error) {
	var results []SearchResult
	var total int
	for rows.Next() {
		var r SearchResult
		var rank float32
		if err := rows.Scan(
			&r.MessageID, &r.SessionID, &r.Role, &r.CreatedAt,
			&r.SessionTitle, &r.Snippet, &rank, &total,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning search result: %w", err)
		}
		r.Rank = float64(rank)
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterating search results: %w", err)
	}
	return results, total, nil
}

// escapeLike escapes LIKE metacharacters in a user-provided search term.
// Backslash MUST be escaped first to avoid double-escaping.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`) // must be first
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// DeleteOldSessions deletes sessions (and their messages via CASCADE) older than cutoff.
// Returns the number of deleted sessions.
//
// PRIVILEGED: This is a cross-tenant operation intended only for the background
// retention scheduler (memory.Scheduler). It must NOT be exposed via any API endpoint.
func (s *Store) DeleteOldSessions(ctx context.Context, cutoff time.Time) (int, error) {
	if s.pool == nil {
		return 0, fmt.Errorf("database pool is required for retention cleanup")
	}
	if cutoff.After(time.Now()) {
		return 0, fmt.Errorf("cutoff cannot be in the future")
	}

	const batchSize = 1000
	var total int
	for {
		select {
		case <-ctx.Done():
			return total, fmt.Errorf("deleting old sessions: %w", ctx.Err())
		default:
		}
		tag, err := s.pool.Exec(ctx,
			`DELETE FROM sessions WHERE id IN (
				SELECT id FROM sessions WHERE updated_at < $1 LIMIT $2
			)`, cutoff, batchSize,
		)
		if err != nil {
			return total, fmt.Errorf("deleting old sessions: %w", err)
		}
		n := int(tag.RowsAffected())
		total += n
		if n == 0 {
			break
		}
	}
	return total, nil
}

// CountSessions returns the number of sessions owned by the given user.
func (s *Store) CountSessions(ctx context.Context, ownerID string) (int, error) {
	if s.pool == nil {
		return 0, fmt.Errorf("database pool is required for count")
	}
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM sessions WHERE owner_id = $1`, ownerID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting sessions: %w", err)
	}
	return count, nil
}

// CountMessagesForSession returns the number of messages in a single session.
func (s *Store) CountMessagesForSession(ctx context.Context, sessionID uuid.UUID) (int, error) {
	if s.pool == nil {
		return 0, fmt.Errorf("database pool is required for count")
	}
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM messages WHERE session_id = $1`, sessionID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting messages for session %s: %w", sessionID, err)
	}
	return count, nil
}

// CountMessages returns the total number of messages across all sessions owned by the given user.
func (s *Store) CountMessages(ctx context.Context, ownerID string) (int, error) {
	if s.pool == nil {
		return 0, fmt.Errorf("database pool is required for count")
	}
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM messages m JOIN sessions s ON s.id = m.session_id WHERE s.owner_id = $1`, ownerID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting messages: %w", err)
	}
	return count, nil
}

// sqlcSessionToSession converts sqlc.Session to the application Session type.
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
