package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/spf13/viper"
)

// Config 存儲應用配置
type Config struct {
	// AI 配置
	ModelName   string  `mapstructure:"model_name"`
	Temperature float32 `mapstructure:"temperature"`
	MaxTokens   int     `mapstructure:"max_tokens"`

	// 對話歷史配置
	MaxHistoryMessages int `mapstructure:"max_history_messages"` // 最大保留的對話訊息數（0 表示無限制）

	// 儲存配置
	DatabasePath string `mapstructure:"database_path"`

	// API Keys
	GeminiAPIKey string `mapstructure:"gemini_api_key"`
}

// Load 載入配置
// 優先順序：環境變數 > 配置文件 > 預設值
func Load() (*Config, error) {
	// 配置目錄: ~/.koopa/
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configDir := filepath.Join(home, ".koopa")

	// 確保目錄存在
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, err
	}

	// 設定 Viper
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configDir)
	viper.AddConfigPath(".") // 也支援當前目錄

	// 設定預設值
	viper.SetDefault("model_name", "gemini-2.5-flash")
	viper.SetDefault("temperature", 0.7)
	viper.SetDefault("max_tokens", 2048)
	viper.SetDefault("max_history_messages", 50) // 預設保留最近 50 則訊息（約 25 輪對話）
	viper.SetDefault("database_path", filepath.Join(configDir, "koopa.db"))

	// 讀取配置檔案（如果存在）
	if err := viper.ReadInConfig(); err != nil {
		// 配置文件不存在不算錯誤，使用預設值
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	// 環境變數設定（使用 KOOPA_ 前綴）
	// 明確綁定每個配置鍵到對應的環境變數
	viper.SetEnvPrefix("KOOPA")
	viper.BindEnv("model_name")
	viper.BindEnv("temperature")
	viper.BindEnv("max_tokens")
	viper.BindEnv("max_history_messages")
	viper.BindEnv("database_path")
	viper.BindEnv("gemini_api_key")

	// 使用 Unmarshal 自動映射到結構體（類型安全）
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("無法解析配置: %w", err)
	}

	return &cfg, nil
}

// GetPlugins 返回 Genkit plugins
func (c *Config) GetPlugins() []any {
	return []any{&googlegenai.GoogleAI{}}
}

// Validate 驗證配置
func (c *Config) Validate() error {
	if c.GeminiAPIKey == "" {
		return &ConfigError{
			Field:   "GEMINI_API_KEY",
			Message: "Gemini API key is required. Set GEMINI_API_KEY environment variable or add it to config file.",
		}
	}
	return nil
}

// ConfigError 配置錯誤
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}
