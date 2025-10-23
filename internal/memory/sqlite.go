package memory

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteMemory 實現基於 SQLite 的記憶系統
type SQLiteMemory struct {
	db *sql.DB
}

// NewSQLiteMemory 創建新的 SQLite 記憶實例
func NewSQLiteMemory(dbPath string) (*SQLiteMemory, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// 啟用外鍵約束
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// 初始化資料庫結構
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return &SQLiteMemory{db: db}, nil
}

// CreateSession 創建新的對話會話
func (m *SQLiteMemory) CreateSession(ctx context.Context, title string) (*Session, error) {
	now := time.Now()
	result, err := m.db.ExecContext(ctx,
		"INSERT INTO sessions (title, created_at, updated_at) VALUES (?, ?, ?)",
		title, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get session id: %w", err)
	}

	return &Session{
		ID:        id,
		Title:     title,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// GetSession 獲取指定的會話
func (m *SQLiteMemory) GetSession(ctx context.Context, sessionID int64) (*Session, error) {
	var session Session
	err := m.db.QueryRowContext(ctx,
		"SELECT id, title, created_at, updated_at FROM sessions WHERE id = ?",
		sessionID,
	).Scan(&session.ID, &session.Title, &session.CreatedAt, &session.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session not found: %d", sessionID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

// ListSessions 列出最近的會話
func (m *SQLiteMemory) ListSessions(ctx context.Context, limit int) ([]*Session, error) {
	rows, err := m.db.QueryContext(ctx,
		"SELECT id, title, created_at, updated_at FROM sessions ORDER BY updated_at DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		var session Session
		if err := rows.Scan(&session.ID, &session.Title, &session.CreatedAt, &session.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, &session)
	}

	return sessions, nil
}

// UpdateSessionTitle 更新會話標題
func (m *SQLiteMemory) UpdateSessionTitle(ctx context.Context, sessionID int64, title string) error {
	result, err := m.db.ExecContext(ctx,
		"UPDATE sessions SET title = ?, updated_at = ? WHERE id = ?",
		title, time.Now(), sessionID,
	)
	if err != nil {
		return fmt.Errorf("failed to update session title: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("session not found: %d", sessionID)
	}

	return nil
}

// DeleteSession 刪除會話（級聯刪除相關訊息）
func (m *SQLiteMemory) DeleteSession(ctx context.Context, sessionID int64) error {
	result, err := m.db.ExecContext(ctx, "DELETE FROM sessions WHERE id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("session not found: %d", sessionID)
	}

	return nil
}

// AddMessage 添加訊息到會話
func (m *SQLiteMemory) AddMessage(ctx context.Context, sessionID int64, role, content string) (*Message, error) {
	now := time.Now()
	result, err := m.db.ExecContext(ctx,
		"INSERT INTO messages (session_id, role, content, created_at) VALUES (?, ?, ?, ?)",
		sessionID, role, content, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to add message: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get message id: %w", err)
	}

	// 更新會話的 updated_at
	if _, err := m.db.ExecContext(ctx,
		"UPDATE sessions SET updated_at = ? WHERE id = ?",
		now, sessionID,
	); err != nil {
		return nil, fmt.Errorf("failed to update session timestamp: %w", err)
	}

	return &Message{
		ID:        id,
		SessionID: sessionID,
		Role:      role,
		Content:   content,
		CreatedAt: now,
	}, nil
}

// GetMessages 獲取會話的所有訊息
func (m *SQLiteMemory) GetMessages(ctx context.Context, sessionID int64, limit int) ([]*Message, error) {
	query := "SELECT id, session_id, role, content, created_at FROM messages WHERE session_id = ? ORDER BY created_at ASC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := m.db.QueryContext(ctx, query, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.ID, &msg.SessionID, &msg.Role, &msg.Content, &msg.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}
		messages = append(messages, &msg)
	}

	return messages, nil
}

// GetRecentMessages 獲取會話的最近 N 條訊息
func (m *SQLiteMemory) GetRecentMessages(ctx context.Context, sessionID int64, limit int) ([]*Message, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, session_id, role, content, created_at
		 FROM messages
		 WHERE session_id = ?
		 ORDER BY created_at DESC
		 LIMIT ?`,
		sessionID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.ID, &msg.SessionID, &msg.Role, &msg.Content, &msg.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}
		messages = append(messages, &msg)
	}

	// 反轉順序，使其按時間正序
	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		messages[i], messages[j] = messages[j], messages[i]
	}

	return messages, nil
}

// SetPreference 設定用戶偏好
func (m *SQLiteMemory) SetPreference(ctx context.Context, key, value string) error {
	_, err := m.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO preferences (key, value) VALUES (?, ?)",
		key, value,
	)
	if err != nil {
		return fmt.Errorf("failed to set preference: %w", err)
	}
	return nil
}

// GetPreference 獲取用戶偏好
func (m *SQLiteMemory) GetPreference(ctx context.Context, key string) (string, error) {
	var value string
	err := m.db.QueryRowContext(ctx,
		"SELECT value FROM preferences WHERE key = ?",
		key,
	).Scan(&value)

	if err == sql.ErrNoRows {
		return "", fmt.Errorf("preference not found: %s", key)
	}
	if err != nil {
		return "", fmt.Errorf("failed to get preference: %w", err)
	}

	return value, nil
}

// ListPreferences 列出所有偏好設定
func (m *SQLiteMemory) ListPreferences(ctx context.Context) ([]*Preference, error) {
	rows, err := m.db.QueryContext(ctx, "SELECT key, value FROM preferences ORDER BY key")
	if err != nil {
		return nil, fmt.Errorf("failed to list preferences: %w", err)
	}
	defer rows.Close()

	var prefs []*Preference
	for rows.Next() {
		var pref Preference
		if err := rows.Scan(&pref.Key, &pref.Value); err != nil {
			return nil, fmt.Errorf("failed to scan preference: %w", err)
		}
		prefs = append(prefs, &pref)
	}

	return prefs, nil
}

// Close 關閉資料庫連接
func (m *SQLiteMemory) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}
