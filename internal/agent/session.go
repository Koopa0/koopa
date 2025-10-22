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

// PersistedPart 穩定的持久化 Part 結構
// 這個結構獨立於 Genkit 的內部實現，確保在 Genkit 版本升級時會話數據仍然有效
type PersistedPart struct {
	// Text 文字內容（如果這是文字 Part）
	Text string `json:"text,omitempty"`

	// Media 媒體內容（如果這是媒體 Part）
	Media *struct {
		ContentType string `json:"content_type"`
		Data        string `json:"data"` // base64 編碼的資料或 URL
	} `json:"media,omitempty"`

	// ToolRequest 工具調用請求（如果這是工具調用 Part）
	ToolRequest *struct {
		Name  string         `json:"name"`
		Input map[string]any `json:"input"`
	} `json:"tool_request,omitempty"`

	// ToolResponse 工具調用回應（如果這是工具回應 Part）
	ToolResponse *struct {
		Name   string         `json:"name"`
		Output map[string]any `json:"output"`
	} `json:"tool_response,omitempty"`
}

// PersistedMessage 穩定的持久化 Message 結構
// 這個結構獨立於 Genkit 的內部實現，確保在 Genkit 版本升級時會話數據仍然有效
type PersistedMessage struct {
	Role    string           `json:"role"` // "user", "model", "system", "tool"
	Content []*PersistedPart `json:"content"`
}

// SessionData 會話數據結構
type SessionData struct {
	ID        string              `json:"id"`
	Messages  []*PersistedMessage `json:"messages"`
	Metadata  map[string]any      `json:"metadata"`
	CreatedAt time.Time           `json:"created_at"`
	UpdatedAt time.Time           `json:"updated_at"`
}

// convertAIMessageToPersisted 將 ai.Message 轉換為 PersistedMessage
func convertAIMessageToPersisted(msg *ai.Message) (*PersistedMessage, error) {
	if msg == nil {
		return nil, fmt.Errorf("message 不能為 nil")
	}

	persisted := &PersistedMessage{
		Role:    string(msg.Role),
		Content: make([]*PersistedPart, 0, len(msg.Content)),
	}

	for _, part := range msg.Content {
		persistedPart := &PersistedPart{}

		// 處理文字 Part
		if part.IsText() {
			persistedPart.Text = part.Text
		}

		// 處理媒體 Part
		if part.IsMedia() {
			persistedPart.Media = &struct {
				ContentType string `json:"content_type"`
				Data        string `json:"data"`
			}{
				ContentType: part.ContentType,
				Data:        part.Text, // 媒體 Part 的資料存儲在 Text 欄位中
			}
		}

		// 處理工具請求 Part
		if part.IsToolRequest() {
			input, ok := part.ToolRequest.Input.(map[string]any)
			if !ok {
				// 如果無法轉換，嘗試使用空 map
				input = make(map[string]any)
			}
			persistedPart.ToolRequest = &struct {
				Name  string         `json:"name"`
				Input map[string]any `json:"input"`
			}{
				Name:  part.ToolRequest.Name,
				Input: input,
			}
		}

		// 處理工具回應 Part
		if part.IsToolResponse() {
			output, ok := part.ToolResponse.Output.(map[string]any)
			if !ok {
				// 如果無法轉換，嘗試使用空 map
				output = make(map[string]any)
			}
			persistedPart.ToolResponse = &struct {
				Name   string         `json:"name"`
				Output map[string]any `json:"output"`
			}{
				Name:   part.ToolResponse.Name,
				Output: output,
			}
		}

		persisted.Content = append(persisted.Content, persistedPart)
	}

	return persisted, nil
}

// convertPersistedToAIMessage 將 PersistedMessage 轉換回 ai.Message
func convertPersistedToAIMessage(persisted *PersistedMessage) (*ai.Message, error) {
	if persisted == nil {
		return nil, fmt.Errorf("persisted message 不能為 nil")
	}

	parts := make([]*ai.Part, 0, len(persisted.Content))

	for _, persistedPart := range persisted.Content {
		// 重建文字 Part
		if persistedPart.Text != "" && persistedPart.Media == nil &&
			persistedPart.ToolRequest == nil && persistedPart.ToolResponse == nil {
			parts = append(parts, ai.NewTextPart(persistedPart.Text))
			continue
		}

		// 重建媒體 Part
		if persistedPart.Media != nil {
			parts = append(parts, ai.NewMediaPart(
				persistedPart.Media.ContentType,
				persistedPart.Media.Data,
			))
			continue
		}

		// 重建工具請求 Part
		if persistedPart.ToolRequest != nil {
			parts = append(parts, ai.NewToolRequestPart(&ai.ToolRequest{
				Name:  persistedPart.ToolRequest.Name,
				Input: persistedPart.ToolRequest.Input,
			}))
			continue
		}

		// 重建工具回應 Part
		if persistedPart.ToolResponse != nil {
			parts = append(parts, ai.NewToolResponsePart(&ai.ToolResponse{
				Name:   persistedPart.ToolResponse.Name,
				Output: persistedPart.ToolResponse.Output,
			}))
			continue
		}
	}

	// 根據角色創建對應的 Message
	var msg *ai.Message
	switch persisted.Role {
	case "user":
		msg = ai.NewUserMessage(parts...)
	case "model":
		msg = ai.NewModelMessage(parts...)
	case "system":
		msg = ai.NewSystemMessage(parts...)
	case "tool":
		// tool 角色的訊息通常是 model 角色的一部分
		// 如果 Genkit 沒有 NewToolMessage，我們使用 model 角色
		msg = ai.NewModelMessage(parts...)
	default:
		return nil, fmt.Errorf("未知的訊息角色: %s", persisted.Role)
	}
	return msg, nil
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
	store          SessionStore
	currentSession *SessionData
	// 快取當前會話的 ai.Message，避免重複轉換
	cachedMessages []*ai.Message
}

// NewSessionManager 創建新的會話管理器
func NewSessionManager(store SessionStore) *SessionManager {
	return &SessionManager{
		store: store,
	}
}

// CreateSession 創建新會話
func (m *SessionManager) CreateSession(ctx context.Context, systemMessage *ai.Message) (*SessionData, error) {
	// 將 ai.Message 轉換為持久化格式
	persistedMsg, err := convertAIMessageToPersisted(systemMessage)
	if err != nil {
		return nil, fmt.Errorf("無法轉換系統訊息: %w", err)
	}

	session := &SessionData{
		ID:        uuid.New().String(),
		Messages:  []*PersistedMessage{persistedMsg},
		Metadata:  make(map[string]any),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := m.store.Save(ctx, session); err != nil {
		return nil, err
	}

	m.currentSession = session
	m.cachedMessages = []*ai.Message{systemMessage}
	return session, nil
}

// LoadSession 載入現有會話
func (m *SessionManager) LoadSession(ctx context.Context, sessionID string) (*SessionData, error) {
	session, err := m.store.Load(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	m.currentSession = session
	// 清除快取，會在 GetMessages 時重新轉換
	m.cachedMessages = nil
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

	// 轉換為持久化格式
	persistedMsg, err := convertAIMessageToPersisted(message)
	if err != nil {
		return fmt.Errorf("無法轉換訊息: %w", err)
	}

	m.currentSession.Messages = append(m.currentSession.Messages, persistedMsg)
	// 同時更新快取
	if m.cachedMessages != nil {
		m.cachedMessages = append(m.cachedMessages, message)
	}
	return nil
}

// GetMessages 獲取當前會話的所有消息
func (m *SessionManager) GetMessages() []*ai.Message {
	if m.currentSession == nil {
		return nil
	}

	// 如果已有快取，直接返回
	if m.cachedMessages != nil && len(m.cachedMessages) == len(m.currentSession.Messages) {
		return m.cachedMessages
	}

	// 將持久化格式轉換回 ai.Message
	messages := make([]*ai.Message, 0, len(m.currentSession.Messages))
	for _, persistedMsg := range m.currentSession.Messages {
		msg, err := convertPersistedToAIMessage(persistedMsg)
		if err != nil {
			// 記錄錯誤但繼續處理其他訊息
			continue
		}
		messages = append(messages, msg)
	}

	// 更新快取
	m.cachedMessages = messages
	return messages
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
		m.cachedMessages = nil
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
	m.cachedMessages = nil
}
