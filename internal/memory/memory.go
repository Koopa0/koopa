package memory

import (
	"context"
	"time"
)

// Message 代表一則對話訊息
type Message struct {
	ID        int64
	SessionID int64
	Role      string // "user" or "model"
	Content   string
	CreatedAt time.Time
}

// Session 代表一個對話會話
type Session struct {
	ID        int64
	Title     string // 會話標題（可自動生成或用戶指定）
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Preference 代表用戶偏好設定
type Preference struct {
	Key   string
	Value string
}

// Memory 定義記憶系統接口
type Memory interface {
	// Session 管理
	CreateSession(ctx context.Context, title string) (*Session, error)
	GetSession(ctx context.Context, sessionID int64) (*Session, error)
	ListSessions(ctx context.Context, limit int) ([]*Session, error)
	UpdateSessionTitle(ctx context.Context, sessionID int64, title string) error
	DeleteSession(ctx context.Context, sessionID int64) error

	// Message 管理
	AddMessage(ctx context.Context, sessionID int64, role, content string) (*Message, error)
	GetMessages(ctx context.Context, sessionID int64, limit int) ([]*Message, error)
	GetRecentMessages(ctx context.Context, sessionID int64, limit int) ([]*Message, error)

	// Preference 管理
	SetPreference(ctx context.Context, key, value string) error
	GetPreference(ctx context.Context, key string) (string, error)
	ListPreferences(ctx context.Context) ([]*Preference, error)

	// 資源管理
	Close() error
}
