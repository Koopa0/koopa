package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
)

// SessionData 會話數據結構
type SessionData struct {
	ID        string         `json:"id"`
	Messages  []*ai.Message  `json:"messages"`
	Metadata  map[string]any `json:"metadata"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// SessionStore 會話存儲接口
type SessionStore interface {
	// Save 保存會話
	Save(ctx context.Context, session *SessionData) error
	// Load 載入會話
	Load(ctx context.Context, sessionID string) (*SessionData, error)
	// Delete 刪除會話
	Delete(ctx context.Context, sessionID string) error
	// List 列出所有會話 ID
	List(ctx context.Context) ([]string, error)
}

// FileSessionStore 基於檔案的會話存儲實作
type FileSessionStore struct {
	basePath string
}

// NewFileSessionStore 創建新的檔案會話存儲
func NewFileSessionStore(basePath string) (*FileSessionStore, error) {
	// 確保目錄存在
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("無法創建會話目錄: %w", err)
	}

	return &FileSessionStore{
		basePath: basePath,
	}, nil
}

// Save 保存會話到檔案
func (s *FileSessionStore) Save(ctx context.Context, session *SessionData) error {
	session.UpdatedAt = time.Now()

	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fmt.Errorf("無法序列化會話: %w", err)
	}

	filePath := filepath.Join(s.basePath, session.ID+".json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("無法寫入會話檔案: %w", err)
	}

	return nil
}

// Load 從檔案載入會話
func (s *FileSessionStore) Load(ctx context.Context, sessionID string) (*SessionData, error) {
	filePath := filepath.Join(s.basePath, sessionID+".json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("會話不存在: %s", sessionID)
		}
		return nil, fmt.Errorf("無法讀取會話檔案: %w", err)
	}

	var session SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("無法解析會話數據: %w", err)
	}

	return &session, nil
}

// Delete 刪除會話檔案
func (s *FileSessionStore) Delete(ctx context.Context, sessionID string) error {
	filePath := filepath.Join(s.basePath, sessionID+".json")

	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("會話不存在: %s", sessionID)
		}
		return fmt.Errorf("無法刪除會話檔案: %w", err)
	}

	return nil
}

// List 列出所有會話 ID
func (s *FileSessionStore) List(ctx context.Context) ([]string, error) {
	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		return nil, fmt.Errorf("無法讀取會話目錄: %w", err)
	}

	var sessionIDs []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			// 移除 .json 副檔名
			sessionID := entry.Name()[:len(entry.Name())-5]
			sessionIDs = append(sessionIDs, sessionID)
		}
	}

	return sessionIDs, nil
}

// SessionManager 會話管理器
type SessionManager struct {
	store         SessionStore
	currentSession *SessionData
}

// NewSessionManager 創建新的會話管理器
func NewSessionManager(store SessionStore) *SessionManager {
	return &SessionManager{
		store: store,
	}
}

// CreateSession 創建新會話
func (m *SessionManager) CreateSession(ctx context.Context, systemMessage *ai.Message) (*SessionData, error) {
	session := &SessionData{
		ID:        uuid.New().String(),
		Messages:  []*ai.Message{systemMessage},
		Metadata:  make(map[string]any),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := m.store.Save(ctx, session); err != nil {
		return nil, err
	}

	m.currentSession = session
	return session, nil
}

// LoadSession 載入現有會話
func (m *SessionManager) LoadSession(ctx context.Context, sessionID string) (*SessionData, error) {
	session, err := m.store.Load(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	m.currentSession = session
	return session, nil
}

// SaveCurrentSession 保存當前會話
func (m *SessionManager) SaveCurrentSession(ctx context.Context) error {
	if m.currentSession == nil {
		return fmt.Errorf("沒有當前會話")
	}

	return m.store.Save(ctx, m.currentSession)
}

// GetCurrentSession 獲取當前會話
func (m *SessionManager) GetCurrentSession() *SessionData {
	return m.currentSession
}

// AddMessage 添加消息到當前會話
func (m *SessionManager) AddMessage(message *ai.Message) error {
	if m.currentSession == nil {
		return fmt.Errorf("沒有當前會話")
	}

	m.currentSession.Messages = append(m.currentSession.Messages, message)
	return nil
}

// GetMessages 獲取當前會話的所有消息
func (m *SessionManager) GetMessages() []*ai.Message {
	if m.currentSession == nil {
		return nil
	}
	return m.currentSession.Messages
}

// SetMetadata 設置會話元數據
func (m *SessionManager) SetMetadata(key string, value any) error {
	if m.currentSession == nil {
		return fmt.Errorf("沒有當前會話")
	}

	m.currentSession.Metadata[key] = value
	return nil
}

// GetMetadata 獲取會話元數據
func (m *SessionManager) GetMetadata(key string) (any, bool) {
	if m.currentSession == nil {
		return nil, false
	}

	value, ok := m.currentSession.Metadata[key]
	return value, ok
}

// DeleteSession 刪除會話
func (m *SessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	if m.currentSession != nil && m.currentSession.ID == sessionID {
		m.currentSession = nil
	}

	return m.store.Delete(ctx, sessionID)
}

// ListSessions 列出所有會話
func (m *SessionManager) ListSessions(ctx context.Context) ([]string, error) {
	return m.store.List(ctx)
}

// ClearCurrentSession 清除當前會話（不保存）
func (m *SessionManager) ClearCurrentSession() {
	m.currentSession = nil
}
