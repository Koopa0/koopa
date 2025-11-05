package memory

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/koopa0/koopa/internal/database/sqlc"
	"github.com/koopa0/koopa/internal/knowledge"
)

// Message represents a conversation message
type Message struct {
	ID        int64
	SessionID int64
	Role      string
	Content   string
	CreatedAt time.Time
}

// Session represents a conversation session
type Session struct {
	ID        int64
	Title     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Preference represents user preference settings
type Preference struct {
	Key   string
	Value string
}

// Memory implements a hybrid memory system with SQL storage and vector search.
// It stores conversation messages in SQLite and maintains vector embeddings
// in a knowledge store for semantic search capabilities.
type Memory struct {
	db      *sql.DB
	queries *sqlc.Queries
	store   knowledge.VectorStore // Vector store for semantic search (optional)
}

// New creates a new Memory instance with SQL storage.
// The vectorStore parameter is optional - pass nil to disable semantic search.
// This follows Go best practice: "Accept interfaces, return structs".
func New(db *sql.DB, vectorStore knowledge.VectorStore) *Memory {
	return &Memory{
		db:      db,
		queries: sqlc.New(db),
		store:   vectorStore,
	}
}

// CreateSession creates a new conversation session
func (m *Memory) CreateSession(ctx context.Context, title string) (*Session, error) {
	now := time.Now()
	session, err := m.queries.CreateSession(ctx, sqlc.CreateSessionParams{
		Title:     title,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &Session{
		ID:        session.ID,
		Title:     session.Title,
		CreatedAt: session.CreatedAt,
		UpdatedAt: session.UpdatedAt,
	}, nil
}

// GetSession retrieves a specific session
func (m *Memory) GetSession(ctx context.Context, sessionID int64) (*Session, error) {
	session, err := m.queries.GetSession(ctx, sessionID)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session not found: %d", sessionID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &Session{
		ID:        session.ID,
		Title:     session.Title,
		CreatedAt: session.CreatedAt,
		UpdatedAt: session.UpdatedAt,
	}, nil
}

// ListSessions lists recent sessions
func (m *Memory) ListSessions(ctx context.Context, limit int) ([]*Session, error) {
	sessions, err := m.queries.ListSessions(ctx, int64(limit))
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	result := make([]*Session, len(sessions))
	for i, s := range sessions {
		result[i] = &Session{
			ID:        s.ID,
			Title:     s.Title,
			CreatedAt: s.CreatedAt,
			UpdatedAt: s.UpdatedAt,
		}
	}

	return result, nil
}

// UpdateSessionTitle updates the session title
func (m *Memory) UpdateSessionTitle(ctx context.Context, sessionID int64, title string) error {
	err := m.queries.UpdateSessionTitle(ctx, sqlc.UpdateSessionTitleParams{
		Title:     title,
		UpdatedAt: time.Now(),
		ID:        sessionID,
	})
	if err != nil {
		return fmt.Errorf("failed to update session title: %w", err)
	}

	return nil
}

// DeleteSession deletes a session (cascade delete related messages)
func (m *Memory) DeleteSession(ctx context.Context, sessionID int64) error {
	err := m.queries.DeleteSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

// AddMessage adds a message to the session.
// If a knowledge store is configured, the message is also indexed for semantic search.
func (m *Memory) AddMessage(ctx context.Context, sessionID int64, role, content string) (*Message, error) {
	now := time.Now()
	message, err := m.queries.AddMessage(ctx, sqlc.AddMessageParams{
		SessionID: sessionID,
		Role:      role,
		Content:   content,
		CreatedAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add message: %w", err)
	}

	// Update session's updated_at timestamp
	if err := m.queries.UpdateSessionTimestamp(ctx, sqlc.UpdateSessionTimestampParams{
		UpdatedAt: now,
		ID:        sessionID,
	}); err != nil {
		return nil, fmt.Errorf("failed to update session timestamp: %w", err)
	}

	// Index in vector store for semantic search (if available)
	if m.store != nil {
		doc := knowledge.Document{
			ID:      strconv.FormatInt(message.ID, 10),
			Content: content,
			Metadata: map[string]string{
				"source_type": "conversation", // Mark as conversation for filtering
				"session_id":  strconv.FormatInt(sessionID, 10),
				"role":        role,
			},
			CreateAt: now,
		}
		if err := m.store.Add(ctx, doc); err != nil {
			// Log error but don't fail the operation
			// Vector search is a nice-to-have feature, not critical
			slog.Warn("failed to index message in vector store",
				"message_id", message.ID,
				"session_id", sessionID,
				"error", err)
		}
	}

	return &Message{
		ID:        message.ID,
		SessionID: message.SessionID,
		Role:      message.Role,
		Content:   message.Content,
		CreatedAt: message.CreatedAt,
	}, nil
}

// GetMessages retrieves all messages for a session
func (m *Memory) GetMessages(ctx context.Context, sessionID int64, limit int) ([]*Message, error) {
	var messages []sqlc.Message
	var err error

	if limit > 0 {
		messages, err = m.queries.GetMessages(ctx, sqlc.GetMessagesParams{
			SessionID: sessionID,
			Limit:     int64(limit),
		})
	} else {
		messages, err = m.queries.GetAllMessages(ctx, sessionID)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get messages: %w", err)
	}

	result := make([]*Message, len(messages))
	for i, msg := range messages {
		result[i] = &Message{
			ID:        msg.ID,
			SessionID: msg.SessionID,
			Role:      msg.Role,
			Content:   msg.Content,
			CreatedAt: msg.CreatedAt,
		}
	}

	return result, nil
}

// GetRecentMessages retrieves the most recent N messages for a session
func (m *Memory) GetRecentMessages(ctx context.Context, sessionID int64, limit int) ([]*Message, error) {
	messages, err := m.queries.GetRecentMessages(ctx, sqlc.GetRecentMessagesParams{
		SessionID: sessionID,
		Limit:     int64(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get recent messages: %w", err)
	}

	// Reverse the order to chronological order
	result := make([]*Message, len(messages))
	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		result[i] = &Message{
			ID:        messages[j].ID,
			SessionID: messages[j].SessionID,
			Role:      messages[j].Role,
			Content:   messages[j].Content,
			CreatedAt: messages[j].CreatedAt,
		}
		result[j] = &Message{
			ID:        messages[i].ID,
			SessionID: messages[i].SessionID,
			Role:      messages[i].Role,
			Content:   messages[i].Content,
			CreatedAt: messages[i].CreatedAt,
		}
	}
	// Handle middle element (when slice length is odd)
	if len(messages)%2 != 0 {
		mid := len(messages) / 2
		result[mid] = &Message{
			ID:        messages[mid].ID,
			SessionID: messages[mid].SessionID,
			Role:      messages[mid].Role,
			Content:   messages[mid].Content,
			CreatedAt: messages[mid].CreatedAt,
		}
	}

	return result, nil
}

// SetPreference sets a user preference
func (m *Memory) SetPreference(ctx context.Context, key, value string) error {
	err := m.queries.SetPreference(ctx, sqlc.SetPreferenceParams{
		Key:   key,
		Value: value,
	})
	if err != nil {
		return fmt.Errorf("failed to set preference: %w", err)
	}
	return nil
}

// GetPreference retrieves a user preference
func (m *Memory) GetPreference(ctx context.Context, key string) (string, error) {
	pref, err := m.queries.GetPreference(ctx, key)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("preference not found: %s", key)
	}
	if err != nil {
		return "", fmt.Errorf("failed to get preference: %w", err)
	}

	return pref.Value, nil
}

// ListPreferences lists all preference settings
func (m *Memory) ListPreferences(ctx context.Context) ([]*Preference, error) {
	prefs, err := m.queries.ListPreferences(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list preferences: %w", err)
	}

	result := make([]*Preference, len(prefs))
	for i, pref := range prefs {
		result[i] = &Preference{
			Key:   pref.Key,
			Value: pref.Value,
		}
	}

	return result, nil
}

// SearchMessages performs semantic search on conversation history.
// Returns messages most similar to the query, ranked by similarity score.
// Only searches messages (not documents or other knowledge sources).
// Requires a knowledge store to be configured; returns error if not available.
func (m *Memory) SearchMessages(ctx context.Context, query string, topK int) ([]*Message, error) {
	if m.store == nil {
		return nil, fmt.Errorf("semantic search not available: knowledge store not configured")
	}

	if topK <= 0 {
		topK = 5 // Default
	}

	// Search in vector store, filtered to conversations only (using functional options)
	results, err := m.store.Search(ctx, query,
		knowledge.WithTopK(topK),
		knowledge.WithFilter("source_type", "conversation"),
	)
	if err != nil {
		return nil, fmt.Errorf("vector search failed: %w", err)
	}

	// Step 1: Collect all message IDs (maintain order from vector search)
	messageIDs := make([]int64, 0, len(results))
	for _, result := range results {
		messageID, err := strconv.ParseInt(result.Document.ID, 10, 64)
		if err != nil {
			continue // Skip invalid IDs
		}
		messageIDs = append(messageIDs, messageID)
	}

	if len(messageIDs) == 0 {
		return []*Message{}, nil
	}

	// Step 2: Batch query all messages at once (solves N+1 query problem)
	dbMessages, err := m.queries.GetMessagesByIDs(ctx, messageIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve messages: %w", err)
	}

	// Step 3: Build messageID → Message map for quick lookup
	messageMap := make(map[int64]*Message, len(dbMessages))
	for _, msg := range dbMessages {
		messageMap[msg.ID] = &Message{
			ID:        msg.ID,
			SessionID: msg.SessionID,
			Role:      msg.Role,
			Content:   msg.Content,
			CreatedAt: msg.CreatedAt,
		}
	}

	// Step 4: Reconstruct result in original similarity order
	messages := make([]*Message, 0, len(dbMessages))
	for _, id := range messageIDs {
		if msg, exists := messageMap[id]; exists {
			messages = append(messages, msg)
		}
		// If message was deleted, skip it (already handled by map lookup)
	}

	return messages, nil
}

// Close closes the database connection
func (m *Memory) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}
